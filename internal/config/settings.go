// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2025 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU General Public License, Version 3 (GPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/gpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// SMTPSettings holds the SMTP server configuration for sending alert emails
type SMTPSettings struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
	UseTLS   bool   `json:"useTLS"`
}

// AppSettings holds the main UI settings and Fail2ban configuration
type AppSettings struct {
	Language       string       `json:"language"`
	Debug          bool         `json:"debug"`
	ReloadNeeded   bool         `json:"reloadNeeded"`
	AlertCountries []string     `json:"alertCountries"`
	SMTP           SMTPSettings `json:"smtp"`

	// Fail2Ban [DEFAULT] section values from jail.local
	BantimeIncrement bool   `json:"bantimeIncrement"`
	IgnoreIP         string `json:"ignoreip"`
	Bantime          string `json:"bantime"`
	Findtime         string `json:"findtime"`
	Maxretry         int    `json:"maxretry"`
	Destemail        string `json:"destemail"`
	//Sender           string `json:"sender"`
}

// init paths to key-files
const (
	settingsFile = "fail2ban-ui-settings.json" // this is relative to where the app was started
	jailFile     = "/etc/fail2ban/jail.local"  // Path to jail.local (to override conf-values from jail.conf)
	jailDFile    = "/etc/fail2ban/jail.d/ui-custom-action.conf"
	actionFile   = "/etc/fail2ban/action.d/ui-custom-action.conf"
)

// in-memory copy of settings
var (
	currentSettings AppSettings
	settingsLock    sync.RWMutex
)

func init() {
	// Attempt to load existing file; if it doesn't exist, create with defaults.
	if err := loadSettings(); err != nil {
		fmt.Println("App settings not found, initializing from jail.local (if exist)")
		if err := initializeFromJailFile(); err != nil {
			fmt.Println("Error reading jail.local:", err)
		}
		setDefaults()
		fmt.Println("Initialized successfully.")

		// save defaults to file
		if err := saveSettings(); err != nil {
			fmt.Println("Failed to save default settings:", err)
		}
	}
	if err := initializeFail2banAction(); err != nil {
		fmt.Println("Error initializing Fail2ban action:", err)
	}
}

// setDefaults populates default values in currentSettings
func setDefaults() {
	settingsLock.Lock()
	defer settingsLock.Unlock()

	if currentSettings.Language == "" {
		currentSettings.Language = "en"
	}
	if currentSettings.AlertCountries == nil {
		currentSettings.AlertCountries = []string{"ALL"}
	}
	if currentSettings.Bantime == "" {
		currentSettings.Bantime = "48h"
	}
	if currentSettings.Findtime == "" {
		currentSettings.Findtime = "30m"
	}
	if currentSettings.Maxretry == 0 {
		currentSettings.Maxretry = 3
	}
	if currentSettings.Destemail == "" {
		currentSettings.Destemail = "alerts@example.com"
	}
	if currentSettings.SMTP.Host == "" {
		currentSettings.SMTP.Host = "smtp.office365.com"
	}
	if currentSettings.SMTP.Port == 0 {
		currentSettings.SMTP.Port = 587
	}
	if currentSettings.SMTP.Username == "" {
		currentSettings.SMTP.Username = "noreply@swissmakers.ch"
	}
	if currentSettings.SMTP.Password == "" {
		currentSettings.SMTP.Password = "password"
	}
	if currentSettings.SMTP.From == "" {
		currentSettings.SMTP.From = "noreply@swissmakers.ch"
	}
	if !currentSettings.SMTP.UseTLS {
		currentSettings.SMTP.UseTLS = true
	}
	if currentSettings.IgnoreIP == "" {
		currentSettings.IgnoreIP = "127.0.0.1/8 ::1"
	}
}

// initializeFromJailFile reads Fail2ban jail.local and merges its settings into currentSettings.
func initializeFromJailFile() error {
	file, err := os.Open(jailFile)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	re := regexp.MustCompile(`^\s*(?P<key>[a-zA-Z0-9_]+)\s*=\s*(?P<value>.+)$`)

	settings := map[string]string{}
	for scanner.Scan() {
		line := scanner.Text()
		if matches := re.FindStringSubmatch(line); matches != nil {
			key := strings.ToLower(matches[1])
			value := matches[2]
			settings[key] = value
		}
	}

	settingsLock.Lock()
	defer settingsLock.Unlock()

	if val, ok := settings["bantime"]; ok {
		currentSettings.Bantime = val
	}
	if val, ok := settings["findtime"]; ok {
		currentSettings.Findtime = val
	}
	if val, ok := settings["maxretry"]; ok {
		if maxRetry, err := strconv.Atoi(val); err == nil {
			currentSettings.Maxretry = maxRetry
		}
	}
	if val, ok := settings["ignoreip"]; ok {
		currentSettings.IgnoreIP = val
	}
	if val, ok := settings["destemail"]; ok {
		currentSettings.Destemail = val
	}
	/*if val, ok := settings["sender"]; ok {
		currentSettings.Sender = val
	}*/

	return nil
}

// initializeFail2banAction writes a custom action configuration for Fail2ban to use AlertCountries.
func initializeFail2banAction() error {
	// Ensure the jail.local is configured correctly
	if err := setupGeoCustomAction(); err != nil {
		fmt.Println("Error setup GeoCustomAction in jail.local:", err)
	}
	// Ensure the jail.d config file is set up
	if err := ensureJailDConfig(); err != nil {
		fmt.Println("Error setting up jail.d configuration:", err)
	}
	// Write the fail2ban action file
	return writeFail2banAction()
}

// setupGeoCustomAction checks and replaces the default action in jail.local with our from fail2ban-UI
func setupGeoCustomAction() error {
	file, err := os.Open(jailFile)
	if err != nil {
		return err // File not found or inaccessible
	}
	defer file.Close()

	var lines []string
	actionPattern := regexp.MustCompile(`^\s*action\s*=\s*%(.*?)\s*$`)
	alreadyModified := false
	actionFound := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Check if we already modified the file (prevent duplicate modifications)
		if strings.Contains(line, "# Custom Fail2Ban action applied") {
			alreadyModified = true
		}

		// Look for an existing action definition
		if actionPattern.MatchString(line) && !alreadyModified {
			actionFound = true

			// Comment out the existing action line
			lines = append(lines, "# "+line)

			// Add our replacement action with a comment marker
			lines = append(lines, "# Custom Fail2Ban action applied by fail2ban-ui")
			lines = append(lines, "action = %(action_mwlg)s")
			continue
		}

		// Store the original line
		lines = append(lines, line)
	}

	// If no action was found, no need to modify the file
	if !actionFound || alreadyModified {
		return nil
	}

	// Write back the modified lines
	output := strings.Join(lines, "\n")
	return os.WriteFile(jailFile, []byte(output), 0644)
}

// ensureJailDConfig checks if the jail.d file exists and creates it if necessary
func ensureJailDConfig() error {
	// Check if the file already exists
	if _, err := os.Stat(jailDFile); err == nil {
		// File already exists, do nothing
		DebugLog("Custom jail.d configuration already exists.")
		return nil
	}

	// Define the content for the custom jail.d configuration
	jailDConfig := `[DEFAULT]
# Custom Fail2Ban action using geo-filter for email alerts

action_mwlg = %(action_)s
             ui-custom-action[sender="%(sender)s", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]
`
	// Write the new configuration file
	err := os.WriteFile(jailDFile, []byte(jailDConfig), 0644)
	if err != nil {
		return fmt.Errorf("failed to write jail.d config: %v", err)
	}

	DebugLog("Created custom jail.d configuration at: %v", jailDFile)
	return nil
}

// writeFail2banAction creates or updates the action file with the AlertCountries.
func writeFail2banAction() error {
	// Define the Fail2Ban action file content
	actionConfig := `[INCLUDES]

before = sendmail-common.conf
         mail-whois-common.conf
         helpers-common.conf

[Definition]

# Bypass ban/unban for restored tickets
norestored = 1

# Option: actionban
# This executes a cURL request to notify our API when an IP is banned.

actionban = /usr/bin/curl -X POST http://127.0.0.1:8080/api/ban \
     -H "Content-Type: application/json" \
     -d "$(jq -n --arg ip '<ip>' \
                 --arg jail '<name>' \
                 --arg hostname '<fq-hostname>' \
                 --arg failures '<failures>' \
                 --arg whois "$(whois <ip> || echo 'missing whois program')" \
                 --arg logs "$(tac <logpath> | grep <grepopts> -wF <ip>)" \
                 '{ip: $ip, jail: $jail, hostname: $hostname, failures: $failures, whois: $whois, logs: $logs}')"

[Init]

# Default name of the chain
name = default

# Path to log files containing relevant lines for the abuser IP
logpath = /dev/null

# Number of log lines to include in the email
# grepmax = 1000
# grepopts = -m <grepmax>`

	// Write the action file
	err := os.WriteFile(actionFile, []byte(actionConfig), 0644)
	if err != nil {
		return fmt.Errorf("failed to write action file: %w", err)
	}

	DebugLog("Custom-action file successfully written to %s\n", actionFile)
	return nil
}

// loadSettings reads fail2ban-ui-settings.json into currentSettings.
func loadSettings() error {
	DebugLog("----------------------------")
	DebugLog("loadSettings called (settings.go)") // entry point
	data, err := os.ReadFile(settingsFile)
	if os.IsNotExist(err) {
		return err // triggers setDefaults + save
	}
	if err != nil {
		return err
	}

	var s AppSettings
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	settingsLock.Lock()
	defer settingsLock.Unlock()
	currentSettings = s
	return nil
}

// saveSettings writes currentSettings to JSON
func saveSettings() error {
	DebugLog("----------------------------")
	DebugLog("saveSettings called (settings.go)") // entry point

	b, err := json.MarshalIndent(currentSettings, "", "  ")
	if err != nil {
		DebugLog("Error marshalling settings: %v", err) // Debug
		return err
	}
	DebugLog("Settings marshaled, writing to file...") // Log marshaling success
	err = os.WriteFile(settingsFile, b, 0644)
	if err != nil {
		DebugLog("Error writing to file: %v", err) // Debug
	}
	// Update the Fail2ban action file
	return writeFail2banAction()
}

// GetSettings returns a copy of the current settings
func GetSettings() AppSettings {
	settingsLock.RLock()
	defer settingsLock.RUnlock()
	return currentSettings
}

// MarkReloadNeeded sets reloadNeeded = true and saves JSON
func MarkReloadNeeded() error {
	settingsLock.Lock()
	defer settingsLock.Unlock()

	currentSettings.ReloadNeeded = true
	return saveSettings()
}

// MarkReloadDone sets reloadNeeded = false and saves JSON
func MarkReloadDone() error {
	settingsLock.Lock()
	defer settingsLock.Unlock()

	currentSettings.ReloadNeeded = false
	return saveSettings()
}

// UpdateSettings merges new settings with old and sets reloadNeeded if needed
func UpdateSettings(new AppSettings) (AppSettings, error) {
	settingsLock.Lock()
	defer settingsLock.Unlock()

	DebugLog("--- Locked settings for update ---") // Log lock acquisition

	old := currentSettings

	// If certain fields change, we mark reload needed
	if old.BantimeIncrement != new.BantimeIncrement ||
		old.IgnoreIP != new.IgnoreIP ||
		old.Bantime != new.Bantime ||
		old.Findtime != new.Findtime ||
		//old.Maxretry != new.Maxretry ||
		old.Destemail != new.Destemail ||
		//old.Sender != new.Sender {
		old.Maxretry != new.Maxretry {
		new.ReloadNeeded = true
	} else {
		// preserve previous ReloadNeeded if it was already true
		new.ReloadNeeded = new.ReloadNeeded || old.ReloadNeeded
	}

	// Countries change? Currently also requires a reload
	if !equalStringSlices(old.AlertCountries, new.AlertCountries) {
		new.ReloadNeeded = true
	}

	currentSettings = new
	DebugLog("New settings applied: %v", currentSettings) // Log settings applied

	// persist to file
	if err := saveSettings(); err != nil {
		fmt.Println("Error saving settings:", err) // Log save error
		return currentSettings, err
	}
	fmt.Println("Settings saved to file successfully") // Log save success
	return currentSettings, nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]bool)
	for _, x := range a {
		m[x] = false
	}
	for _, x := range b {
		if _, ok := m[x]; !ok {
			return false
		}
	}
	return true
}
