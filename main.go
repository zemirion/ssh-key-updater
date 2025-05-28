package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

type StringSlice []string

func (s *StringSlice) String() string {
	return strings.Join(*s, ",")
}

func (s *StringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type SSHMonitor struct {
	controlDirs    []string
	publicKeys     []string
	watcher        *fsnotify.Watcher
	processedHosts map[string]string
	stateFile      string
	ignoreState    bool
	onlyUsers      []string
	pidFile        string
}

func checkPIDFile(pidFile string) error {
	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read PID file %s: %w", pidFile, err)
	}

	pidStr := strings.TrimSpace(string(pidData))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		log.Printf("Warning: invalid PID in file %s: %s", pidFile, pidStr)
		return nil
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		log.Printf("Warning: PID %d from file not found, assuming stale", pid)
		return nil
	}

	err = process.Signal(syscall.Signal(0))
	if err != nil {
		log.Printf("Warning: PID %d from file is not running, removing stale PID file", pid)
		os.Remove(pidFile)
		return nil
	}

	return fmt.Errorf("ssh-monitor daemon is already running with PID %d", pid)
}

func writePIDFile(pidFile string) error {
	pidDir := filepath.Dir(pidFile)
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		return fmt.Errorf("failed to create PID directory: %w", err)
	}

	pid := os.Getpid()
	pidData := fmt.Sprintf("%d\n", pid)

	if err := os.WriteFile(pidFile, []byte(pidData), 0644); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	log.Printf("Created PID file: %s (PID: %d)", pidFile, pid)
	return nil
}

func removePIDFile(pidFile string) {
	if err := os.Remove(pidFile); err != nil {
		log.Printf("Warning: failed to remove PID file %s: %v", pidFile, err)
	} else {
		log.Printf("Removed PID file: %s", pidFile)
	}
}

func daemonize() error {
	// Check if we're already daemonized
	if os.Getppid() == 1 {
		return nil // Already a daemon
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	var args []string
	for _, arg := range os.Args[1:] {
		if arg == "--daemon" || arg == "-daemon" {
			continue
		}

		if strings.HasPrefix(arg, "--daemon=") || strings.HasPrefix(arg, "-daemon=") {
			continue
		}

		args = append(args, arg)
	}

	args = append(args, "--daemon-child")

	cmd := exec.Command(execPath, args...)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start daemon process: %w", err)
	}

	fmt.Printf("SSH Monitor daemon started with PID: %d\n", cmd.Process.Pid)
	fmt.Printf("Log file: %s\n", getDefaultLogFile())
	os.Exit(0)
	return nil
}

func getDefaultLogFile() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "~/.ssh/ssh-monitor.log"
	}
	return filepath.Join(homeDir, ".ssh", "ssh-monitor.log")
}

func setupLogging(daemon bool, logFile string, truncateLog bool) error {
	fmt.Printf("DEBUG: setupLogging called with daemon=%v, logFile='%s', truncateLog=%v\n", daemon, logFile, truncateLog)

	if daemon {
		if logFile == "" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %w", err)
			}
			logFile = filepath.Join(homeDir, ".ssh", "ssh-monitor.log")
		}

		fmt.Printf("DEBUG: Using log file: %s\n", logFile)

		logDir := filepath.Dir(logFile)
		fmt.Printf("DEBUG: Creating log directory: %s\n", logDir)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}

		flags := os.O_CREATE | os.O_WRONLY
		if truncateLog {
			flags |= os.O_TRUNC
		} else {
			flags |= os.O_APPEND
		}

		fmt.Printf("DEBUG: Opening log file with flags: %v\n", flags)

		file, err := os.OpenFile(logFile, flags, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}

		fmt.Printf("DEBUG: Log file opened successfully\n")

		log.SetOutput(file)
		if truncateLog {
			log.Printf("SSH Monitor daemon started (PID: %d) - log truncated", os.Getpid())
		} else {
			log.Printf("SSH Monitor daemon started (PID: %d) - log appended", os.Getpid())
		}

		log.Printf("Logging to: %s", logFile)
		fmt.Printf("DEBUG: Initial log messages written\n")
	} else {
		fmt.Printf("DEBUG: Not daemon mode, skipping log file setup\n")
	}

	return nil
}

func NewSSHMonitor(controlDirs []string, keyFiles []string, useSSHAgent bool, sshAgentKeys []string, ignoreState bool, onlyUsers []string, pidFile string) (*SSHMonitor, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	var expandedDirs []string
	for _, dir := range controlDirs {
		if strings.HasPrefix(dir, "~/") {
			dir = filepath.Join(homeDir, dir[2:])
		}
		expandedDirs = append(expandedDirs, dir)
	}

	for _, controlDir := range expandedDirs {
		if err := os.MkdirAll(controlDir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create control directory %s: %w", controlDir, err)
		}
	}

	publicKeys, err := loadPublicKeys(homeDir, keyFiles, useSSHAgent, sshAgentKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to load public keys: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	stateFile := filepath.Join(homeDir, ".ssh", "ssh-monitor-state.json")

	monitor := &SSHMonitor{
		controlDirs:    expandedDirs,
		publicKeys:     publicKeys,
		watcher:        watcher,
		processedHosts: make(map[string]string),
		stateFile:      stateFile,
		ignoreState:    ignoreState,
		onlyUsers:      onlyUsers,
		pidFile:        pidFile,
	}

	if !ignoreState {
		if err := monitor.loadState(); err != nil {
			log.Printf("Warning: failed to load state file: %v", err)
		}
	} else {
		log.Println("Ignoring existing state file as requested")
	}

	if len(onlyUsers) > 0 {
		log.Printf("Restricting key distribution to users: %v", onlyUsers)
	} else {
		log.Println("No user restrictions - will process all users")
	}

	return monitor, nil
}

func loadPublicKeys(homeDir string, keyFiles []string, useSSHAgent bool, sshAgentKeys []string) ([]string, error) {
	var publicKeys []string
	keySet := make(map[string]bool)
	keyMaterialToFull := make(map[string]string)

	if len(keyFiles) > 0 {
		for _, keyFile := range keyFiles {
			if strings.HasPrefix(keyFile, "~/") {
				keyFile = filepath.Join(homeDir, keyFile[2:])
			}

			if content, err := os.ReadFile(keyFile); err == nil {
				key := strings.TrimSpace(string(content))
				if key != "" {
					keyMaterial := extractKeyMaterial(key)
					if !keySet[keyMaterial] {
						publicKeys = append(publicKeys, key)
						keySet[keyMaterial] = true
						keyMaterialToFull[keyMaterial] = key
						log.Printf("Loaded key from file: %s", keyFile)
					} else {
						log.Printf("Skipping duplicate key from file: %s (same key material, different comment)", keyFile)
					}
				}
			} else {
				log.Printf("Warning: failed to read key file %s: %v", keyFile, err)
			}
		}
	} else {
		sshDir := filepath.Join(homeDir, ".ssh")
		defaultKeyFiles := []string{"id_rsa.pub", "id_ed25519.pub", "id_ecdsa.pub", "id_dsa.pub"}

		for _, keyFile := range defaultKeyFiles {
			keyPath := filepath.Join(sshDir, keyFile)
			if content, err := os.ReadFile(keyPath); err == nil {
				key := strings.TrimSpace(string(content))
				if key != "" {
					keyMaterial := extractKeyMaterial(key)
					if !keySet[keyMaterial] {
						publicKeys = append(publicKeys, key)
						keySet[keyMaterial] = true
						keyMaterialToFull[keyMaterial] = key
						log.Printf("Loaded key from default file: %s", keyPath)
					} else {
						log.Printf("Skipping duplicate key from default file: %s (same key material, different comment)", keyPath)
					}
				}
			}
		}
	}

	if useSSHAgent {
		agentKeys, err := loadKeysFromSSHAgent(sshAgentKeys)
		if err != nil {
			log.Printf("Warning: failed to load keys from SSH agent: %v", err)
		} else {
			for _, key := range agentKeys {
				keyMaterial := extractKeyMaterial(key)
				if !keySet[keyMaterial] {
					publicKeys = append(publicKeys, key)
					keySet[keyMaterial] = true
					keyMaterialToFull[keyMaterial] = key
					log.Printf("Loaded key from SSH agent")
				} else {
					log.Printf("Skipping duplicate key from SSH agent (same key material as file, different comment)")
				}
			}
		}
	}

	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("no public keys found")
	}

	log.Printf("Loaded %d unique public keys (duplicates removed by key material)", len(publicKeys))
	return publicKeys, nil
}

func loadKeysFromSSHAgent(specificKeys []string) ([]string, error) {
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK not set, ssh-agent not running")
	}

	if len(specificKeys) > 0 {
		return loadSpecificKeysFromSSHAgent(specificKeys)
	}

	cmd := exec.Command("ssh-add", "-L")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys from ssh-agent: %w", err)
	}

	var keys []string
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.Contains(line, "The agent has no identities") {
			keys = append(keys, line)
		}
	}

	log.Printf("Loaded %d keys from SSH agent", len(keys))
	return keys, nil
}

func loadSpecificKeysFromSSHAgent(specificKeys []string) ([]string, error) {
	publicKeyCmd := exec.Command("ssh-add", "-L")
	publicKeyOutput, err := publicKeyCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list public keys from ssh-agent: %w", err)
	}

	publicKeyLines := strings.Split(strings.TrimSpace(string(publicKeyOutput)), "\n")

	requestedFingerprints := make(map[string]bool)
	for _, key := range specificKeys {
		normalized := strings.TrimPrefix(key, "SHA256:")
		requestedFingerprints[normalized] = true
		requestedFingerprints["SHA256:"+normalized] = true
	}

	var selectedKeys []string
	for _, publicKeyLine := range publicKeyLines {
		publicKey := strings.TrimSpace(publicKeyLine)
		if publicKey == "" || strings.Contains(publicKey, "The agent has no identities") {
			continue
		}

		fingerprint, err := calculateSSHKeyFingerprint(publicKey)
		if err != nil {
			log.Printf("Warning: failed to calculate fingerprint for key: %v", err)
			continue
		}

		if requestedFingerprints[fingerprint] || requestedFingerprints["SHA256:"+fingerprint] {
			selectedKeys = append(selectedKeys, publicKey)
			log.Printf("Selected SSH agent key with fingerprint: SHA256:%s", fingerprint)
		}
	}

	if len(selectedKeys) == 0 {
		return nil, fmt.Errorf("no matching keys found for specified fingerprints")
	}

	log.Printf("Loaded %d specific keys from SSH agent", len(selectedKeys))
	return selectedKeys, nil
}

func calculateSSHKeyFingerprint(publicKey string) (string, error) {
	parts := strings.Fields(publicKey)
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid public key format")
	}

	cmd := exec.Command("ssh-keygen", "-lf", "/dev/stdin")
	cmd.Stdin = strings.NewReader(publicKey)

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to calculate fingerprint: %w", err)
	}

	outputStr := strings.TrimSpace(string(output))
	parts = strings.Fields(outputStr)
	if len(parts) < 2 {
		return "", fmt.Errorf("unexpected ssh-keygen output format: %s", outputStr)
	}

	fingerprint := parts[1]
	if strings.HasPrefix(fingerprint, "SHA256:") {
		return strings.TrimPrefix(fingerprint, "SHA256:"), nil
	}

	if strings.HasPrefix(fingerprint, "MD5:") {
		return "", fmt.Errorf("MD5 fingerprints not supported, please use SHA256")
	}

	return fingerprint, nil
}

func extractKeyMaterial(publicKey string) string {
	parts := strings.Fields(strings.TrimSpace(publicKey))
	if len(parts) >= 2 {
		return parts[0] + " " + parts[1]
	}
	return strings.TrimSpace(publicKey)
}

func (m *SSHMonitor) loadState() error {
	data, err := os.ReadFile(m.stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("No existing state file found at %s", m.stateFile)
			return nil
		}
		return err
	}

	if err := json.Unmarshal(data, &m.processedHosts); err != nil {
		return fmt.Errorf("failed to parse state file: %w", err)
	}

	log.Printf("Loaded state for %d previously processed hosts from %s", len(m.processedHosts), m.stateFile)
	return nil
}

func (m *SSHMonitor) saveState() error {
	stateDir := filepath.Dir(m.stateFile)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	data, err := json.MarshalIndent(m.processedHosts, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	if err := os.WriteFile(m.stateFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	log.Printf("Saved state for %d hosts to %s", len(m.processedHosts), m.stateFile)
	return nil
}

func parseControlMasterPath(socketPath string) (user, host, port string, err error) {
	filename := filepath.Base(socketPath)

	parts := strings.Split(filename, "@")
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("invalid control master format: %s", filename)
	}

	user = parts[0]
	hostPort := parts[1]

	hostPortParts := strings.Split(hostPort, ":")
	if len(hostPortParts) != 2 {
		return "", "", "", fmt.Errorf("invalid host:port format: %s", hostPort)
	}

	host = hostPortParts[0]
	port = hostPortParts[1]

	return user, host, port, nil
}

func (m *SSHMonitor) buildSSHArgs(user, host, port string) []string {
	var args []string

	args = append(args, "-o", "ControlMaster=no")

	args = append(args, "-o", "ConnectTimeout=10")

	if port != "22" {
		args = append(args, "-p", port)
	}

	args = append(args, fmt.Sprintf("%s@%s", user, host))

	return args
}

func (m *SSHMonitor) runSSHCommand(user, host, port, command string) ([]byte, error) {
	args := m.buildSSHArgs(user, host, port)
	args = append(args, command)

	cmd := exec.Command("ssh", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("SSH command failed: %w", err)
	}

	return output, nil
}

func (m *SSHMonitor) runSSHCommandWithInput(user, host, port, command string, input []byte) error {
	args := m.buildSSHArgs(user, host, port)
	args = append(args, command)

	cmd := exec.Command("ssh", args...)
	cmd.Stdin = strings.NewReader(string(input))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("SSH command failed: %w, output: %s", err, string(output))
	}

	return nil
}

func (m *SSHMonitor) readRemoteFile(user, host, port, filePath string) ([]byte, error) {
	command := fmt.Sprintf("cat %s 2>/dev/null || true", filePath)
	return m.runSSHCommand(user, host, port, command)
}

func (m *SSHMonitor) writeRemoteFile(user, host, port, filePath string, content []byte) error {
	command := "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat > " + filePath + " && chmod 600 " + filePath
	return m.runSSHCommandWithInput(user, host, port, command, content)
}

func (m *SSHMonitor) isUserAllowed(user string) bool {
	if len(m.onlyUsers) == 0 {
		return true
	}

	for _, allowedUser := range m.onlyUsers {
		if user == allowedUser {
			return true
		}
	}

	return false
}

func (m *SSHMonitor) copyKeysToHost(socketPath string) {
	user, host, port, err := parseControlMasterPath(socketPath)
	if err != nil {
		log.Printf("Failed to parse control master path %s: %v", socketPath, err)
		return
	}

	if !m.isUserAllowed(user) {
		log.Printf("Skipping key distribution to %s@%s:%s - user '%s' not in allowed list", user, host, port, user)
		return
	}

	sshTarget := fmt.Sprintf("%s@%s:%s", user, host, port)
	log.Printf("Processing SSH keys for %s (via %s)", sshTarget, socketPath)

	authorizedKeysPath := "~/.ssh/authorized_keys"
	currentContent, err := m.readRemoteFile(user, host, port, authorizedKeysPath)
	if err != nil {
		log.Printf("Failed to read authorized_keys from %s: %v", sshTarget, err)
		return
	}

	var currentKeys []string
	content := strings.TrimSpace(string(currentContent))
	if content != "" {
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				currentKeys = append(currentKeys, line)
			}
		}
	}

	log.Printf("Found %d existing keys on %s", len(currentKeys), sshTarget)

	originalChecksum := fmt.Sprintf("%x", sha256.Sum256(currentContent))

	existingKeyMaterials := make(map[string]bool)
	for _, key := range currentKeys {
		keyMaterial := extractKeyMaterial(key)
		existingKeyMaterials[keyMaterial] = true
	}

	var keysToAdd []string
	keysSkipped := 0
	for _, pubKey := range m.publicKeys {
		keyMaterial := extractKeyMaterial(pubKey)
		if existingKeyMaterials[keyMaterial] {
			keysSkipped++
			log.Printf("Skipping key (already exists with same key material): %s", keyMaterial[:20]+"...")
		} else {
			keysToAdd = append(keysToAdd, pubKey)
		}
	}

	currentPublicKeysContent := strings.Join(m.publicKeys, "\n")
	currentKeysChecksum := fmt.Sprintf("%x", sha256.Sum256([]byte(currentPublicKeysContent)))

	hostKey := fmt.Sprintf("%s@%s:%s", user, host, port)
	lastProcessedChecksum, alreadyProcessed := m.processedHosts[hostKey]

	if len(keysToAdd) == 0 && alreadyProcessed && lastProcessedChecksum == currentKeysChecksum {
		log.Printf("All keys already present on %s and no key changes detected, no action needed", sshTarget)
		return
	}

	if len(keysToAdd) == 0 && !alreadyProcessed {
		if keysSkipped > 0 {
			log.Printf("All %d keys already present on %s (by key material), marking as processed", keysSkipped, sshTarget)
		} else {
			log.Printf("No keys to add to %s, marking as processed", sshTarget)
		}
		m.processedHosts[hostKey] = currentKeysChecksum

		if err := m.saveState(); err != nil {
			log.Printf("Warning: failed to save state: %v", err)
		}
		return
	}

	if len(keysToAdd) > 0 {
		log.Printf("Adding %d new keys to %s (%d skipped as duplicates)", len(keysToAdd), sshTarget, keysSkipped)
	} else {
		log.Printf("Re-processing %s due to key changes", sshTarget)
	}

	var allKeys []string

	allKeys = append(allKeys, currentKeys...)

	allKeys = append(allKeys, keysToAdd...)

	newContent := strings.Join(allKeys, "\n") + "\n"

	recheckContent, err := m.readRemoteFile(user, host, port, authorizedKeysPath)
	if err != nil {
		log.Printf("Failed to recheck authorized_keys on %s: %v", sshTarget, err)
		return
	}

	currentChecksum := fmt.Sprintf("%x", sha256.Sum256(recheckContent))
	if currentChecksum != originalChecksum {
		log.Printf("Remote authorized_keys file changed during processing on %s, aborting update", sshTarget)
		return
	}

	if err := m.writeRemoteFile(user, host, port, authorizedKeysPath, []byte(newContent)); err != nil {
		log.Printf("Failed to write updated authorized_keys to %s: %v", sshTarget, err)
		return
	}

	m.processedHosts[hostKey] = currentKeysChecksum

	if err := m.saveState(); err != nil {
		log.Printf("Warning: failed to save state: %v", err)
	}

	totalKeys := len(allKeys)
	if keysSkipped > 0 {
		log.Printf("Successfully updated authorized_keys on %s: %d total keys (%d added, %d skipped as duplicates)", sshTarget, totalKeys, len(keysToAdd), keysSkipped)
	} else {
		log.Printf("Successfully updated authorized_keys on %s: %d total keys (%d added)", sshTarget, totalKeys, len(keysToAdd))
	}
}

func (m *SSHMonitor) handleControlMasterEvent(event fsnotify.Event) {
	if !event.Has(fsnotify.Create) {
		return
	}

	if info, err := os.Stat(event.Name); err == nil {
		if info.Mode()&os.ModeSocket != 0 {
			log.Printf("New control master detected: %s", event.Name)

			time.Sleep(500 * time.Millisecond)

			go m.copyKeysToHost(event.Name)
		}
	}
}

func (m *SSHMonitor) Start() error {
	for _, controlDir := range m.controlDirs {
		err := m.watcher.Add(controlDir)
		if err != nil {
			return fmt.Errorf("failed to watch control directory %s: %w", controlDir, err)
		}
		log.Printf("Monitoring control master directory: %s", controlDir)
	}

	for _, controlDir := range m.controlDirs {
		entries, err := os.ReadDir(controlDir)
		if err != nil {
			log.Printf("Warning: failed to read control directory %s: %v", controlDir, err)
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				socketPath := filepath.Join(controlDir, entry.Name())
				if info, err := entry.Info(); err == nil && info.Mode()&os.ModeSocket != 0 {
					log.Printf("Found existing control master: %s", socketPath)
					go m.copyKeysToHost(socketPath)
				}
			}
		}
	}

	log.Printf("SSH Control Master Monitor started, watching %d directories", len(m.controlDirs))

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGUSR1)

	go func() {
		for range sigChan {
			log.Println("Received SIGUSR1, refreshing keys for all active connections...")
			m.refreshAllConnections()
		}
	}()

	log.Printf("Send SIGUSR1 to refresh keys on all active connections (kill -USR1 %d)", os.Getpid())

	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return fmt.Errorf("watcher closed")
			}
			m.handleControlMasterEvent(event)

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return fmt.Errorf("watcher error channel closed")
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

func (m *SSHMonitor) refreshAllConnections() {
	log.Println("Refreshing keys for all active control master connections...")

	for _, controlDir := range m.controlDirs {
		entries, err := os.ReadDir(controlDir)
		if err != nil {
			log.Printf("Warning: failed to read control directory %s during refresh: %v", controlDir, err)
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				socketPath := filepath.Join(controlDir, entry.Name())
				if info, err := entry.Info(); err == nil && info.Mode()&os.ModeSocket != 0 {
					log.Printf("Refreshing keys for existing control master: %s", socketPath)
					go m.copyKeysToHost(socketPath)
				}
			}
		}
	}
}

func (m *SSHMonitor) Close() error {
	if m.pidFile != "" {
		removePIDFile(m.pidFile)
	}

	if err := m.saveState(); err != nil {
		log.Printf("Warning: failed to save final state: %v", err)
	}
	return m.watcher.Close()
}

func main() {
	var controlDirs StringSlice
	var keyFiles StringSlice
	var sshAgentKeys StringSlice
	var onlyUsers StringSlice
	var useSSHAgent bool
	var daemon bool
	var daemonChild bool
	var logFile string
	var truncateLog bool
	var ignoreState bool
	var pidFile string

	flag.Var(&controlDirs, "control-dir", "Control master directory to monitor (can be specified multiple times)")
	flag.Var(&keyFiles, "key-file", "Public key file to use (can be specified multiple times)")
	flag.BoolVar(&useSSHAgent, "ssh-agent", false, "Load keys from SSH agent")
	flag.Var(&sshAgentKeys, "ssh-agent-key", "Load specific key from SSH agent by SHA256 fingerprint (can be specified multiple times)")
	flag.Var(&onlyUsers, "only-user", "Only distribute keys to this user (can be specified multiple times, empty = all users)")
	flag.BoolVar(&daemon, "daemon", false, "Run as daemon in background")
	flag.BoolVar(&daemonChild, "daemon-child", false, "Internal flag - indicates this is the daemon child process")
	flag.StringVar(&logFile, "log-file", "", "Log file path when running as daemon (default: ~/.ssh/ssh-monitor.log)")
	flag.BoolVar(&truncateLog, "truncate-log", false, "Truncate log file on startup instead of appending")
	flag.BoolVar(&ignoreState, "ignore-state", false, "Ignore existing state and process all hosts (don't load ~/.ssh/ssh-monitor-state.json)")
	flag.StringVar(&pidFile, "pid-file", "", "PID file path when running as daemon (default: ~/.ssh/ssh-monitor.pid)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s --daemon --ssh-agent\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --ssh-agent-key SHA256:abc123... --control-dir ~/.ssh/controlmaster\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --daemon --key-file ~/.ssh/special_key.pub --log-file ~/ssh-monitor.log\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --ignore-state --ssh-agent  # Process all hosts, ignoring previous state\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --only-user myuser --only-user deploy --ssh-agent  # Only distribute to specific users\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --daemon --pid-file /var/run/ssh-monitor.pid --ssh-agent  # Custom PID file\n", os.Args[0])
	}

	flag.Parse()

	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "Error: Unknown arguments: %v\n\n", flag.Args())
		fmt.Fprintf(os.Stderr, "Note: If you're trying to specify a key fingerprint, use --ssh-agent-key instead of --ssh-agent with a value\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if (daemon || daemonChild) && pidFile == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Failed to get home directory: %v", err)
		}
		pidFile = filepath.Join(homeDir, ".ssh", "ssh-monitor.pid")
	}

	if daemon && !daemonChild {
		if err := checkPIDFile(pidFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			fmt.Fprintf(os.Stderr, "Use 'kill <pid>' to stop the existing daemon, or remove the PID file if it's stale.\n")
			os.Exit(1)
		}
	}

	if daemon && !daemonChild {
		if err := daemonize(); err != nil {
			log.Fatalf("Failed to daemonize: %v", err)
		}
	}

	if daemonChild && pidFile != "" {
		if err := writePIDFile(pidFile); err != nil {
			log.Fatalf("Failed to write PID file: %v", err)
		}

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
		go func() {
			<-sigChan
			log.Println("Received termination signal, shutting down...")
			removePIDFile(pidFile)
			os.Exit(0)
		}()
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if err := setupLogging(daemonChild, logFile, truncateLog); err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}

	if len(sshAgentKeys) > 0 {
		useSSHAgent = true
	}

	if len(controlDirs) == 0 {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Failed to get home directory: %v", err)
		}
		controlDirs = append(controlDirs, filepath.Join(homeDir, ".ssh", "controlmaster"))
	}

	var expandedDirs []string
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get home directory: %v", err)
	}

	for _, dir := range controlDirs {
		if strings.HasPrefix(dir, "~/") {
			dir = filepath.Join(homeDir, dir[2:])
		}
		expandedDirs = append(expandedDirs, dir)
	}

	monitor, err := NewSSHMonitor(expandedDirs, []string(keyFiles), useSSHAgent, []string(sshAgentKeys), ignoreState, []string(onlyUsers), pidFile)
	if err != nil {
		log.Fatalf("Failed to create SSH monitor: %v", err)
	}
	defer monitor.Close()

	if err := monitor.Start(); err != nil {
		log.Fatalf("Monitor failed: %v", err)
	}
}
