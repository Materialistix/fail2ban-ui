package fail2ban

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

// GetAllJails reads jails from both /etc/fail2ban/jail.local and /etc/fail2ban/jail.d directory.
func GetAllJails() ([]JailInfo, error) {
	var jails []JailInfo

	// Parse jails from jail.local
	localPath := "/etc/fail2ban/jail.local"
	localJails, err := parseJailConfigFile(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", localPath, err)
	}
	config.DebugLog("############################")
	config.DebugLog(fmt.Sprintf("%+v", localJails))
	config.DebugLog("############################")

	jails = append(jails, localJails...)

	// Parse jails from jail.d directory, if it exists
	jailDPath := "/etc/fail2ban/jail.d"
	files, err := os.ReadDir(jailDPath)
	if err == nil {
		for _, f := range files {
			if !f.IsDir() && filepath.Ext(f.Name()) == ".conf" {
				fullPath := filepath.Join(jailDPath, f.Name())
				dJails, err := parseJailConfigFile(fullPath)
				if err == nil {
					jails = append(jails, dJails...)
				}
			}
		}
	}
	return jails, nil
}

// parseJailConfigFile parses a jail configuration file and returns a slice of JailInfo.
// It assumes each jail section is defined by [JailName] and that an "enabled" line may exist.
func parseJailConfigFile(path string) ([]JailInfo, error) {
	var jails []JailInfo
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentJail string

	// default value is true if "enabled" is missing; we set it for each section.
	enabled := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			// When a new section starts, save the previous jail if exists.
			if currentJail != "" && currentJail != "DEFAULT" {
				jails = append(jails, JailInfo{
					JailName: currentJail,
					Enabled:  enabled,
				})
			}
			// Start a new jail section.
			currentJail = strings.Trim(line, "[]")
			// Reset to default for the new section.
			enabled = true
		} else if strings.HasPrefix(strings.ToLower(line), "enabled") {
			// Expect format: enabled = true/false
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				value := strings.TrimSpace(parts[1])
				enabled = strings.EqualFold(value, "true")
			}
		}
	}
	// Add the final jail if one exists.
	if currentJail != "" && currentJail != "DEFAULT" {
		jails = append(jails, JailInfo{
			JailName: currentJail,
			Enabled:  enabled,
		})
	}
	return jails, scanner.Err()
}

// UpdateJailEnabledStates updates the enabled state for each jail based on the provided updates map.
// It updates /etc/fail2ban/jail.local and attempts to update any jail.d files as well.
func UpdateJailEnabledStates(updates map[string]bool) error {
	// Update jail.local file
	localPath := "/etc/fail2ban/jail.local"
	if err := updateJailConfigFile(localPath, updates); err != nil {
		return fmt.Errorf("failed to update %s: %w", localPath, err)
	}
	// Update jail.d files (if any)
	jailDPath := "/etc/fail2ban/jail.d"
	files, err := os.ReadDir(jailDPath)
	if err == nil {
		for _, f := range files {
			if !f.IsDir() && filepath.Ext(f.Name()) == ".conf" {
				fullPath := filepath.Join(jailDPath, f.Name())
				// Ignore error here, as jail.d files might not need to be updated.
				_ = updateJailConfigFile(fullPath, updates)
			}
		}
	}
	return nil
}

// updateJailConfigFile updates a single jail configuration file with the new enabled states.
func updateJailConfigFile(path string, updates map[string]bool) error {
	input, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(input), "\n")
	var outputLines []string
	var currentJail string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			currentJail = strings.Trim(trimmed, "[]")
			outputLines = append(outputLines, line)
		} else if strings.HasPrefix(trimmed, "enabled") {
			if val, ok := updates[currentJail]; ok {
				outputLines = append(outputLines, fmt.Sprintf("enabled = %t", val))
				// Remove the update from map to mark it as processed.
				delete(updates, currentJail)
			} else {
				outputLines = append(outputLines, line)
			}
		} else {
			outputLines = append(outputLines, line)
		}
	}
	// For any jails in updates that did not have an "enabled" line, append it.
	for jail, val := range updates {
		outputLines = append(outputLines, fmt.Sprintf("[%s]", jail))
		outputLines = append(outputLines, fmt.Sprintf("enabled = %t", val))
	}
	newContent := strings.Join(outputLines, "\n")
	return os.WriteFile(path, []byte(newContent), 0644)
}
