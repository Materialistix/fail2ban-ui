package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// AppSettings holds both the UI settings (like language) and
// relevant Fail2ban jail/local config options.
type AppSettings struct {
	Language       string   `json:"language"`
	Debug          bool     `json:"debug"`
	ReloadNeeded   bool     `json:"reloadNeeded"`
	AlertCountries []string `json:"alertCountries"`

	// These mirror some Fail2ban [DEFAULT] section parameters from jail.local
	BantimeIncrement bool   `json:"bantimeIncrement"`
	IgnoreIP         string `json:"ignoreip"`
	Bantime          string `json:"bantime"`
	Findtime         string `json:"findtime"`
	Maxretry         int    `json:"maxretry"`
	Destemail        string `json:"destemail"`
	Sender           string `json:"sender"`
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
		fmt.Println("App settings not found, initializing new from jail.local (if exist):", err)
		if err := initializeFromJailFile(); err != nil {
			fmt.Println("Error reading jail.local:", err)
		}
		setDefaults()

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
		currentSettings.AlertCountries = []string{"all"}
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
		currentSettings.Destemail = "alerts@swissmakers.ch"
	}
	if currentSettings.Sender == "" {
		currentSettings.Sender = "noreply@swissmakers.ch"
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
	if val, ok := settings["sender"]; ok {
		currentSettings.Sender = val
	}

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
	return writeFail2banAction(currentSettings.AlertCountries)
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
		fmt.Println("Custom jail.d configuration already exists.")
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

	fmt.Println("Created custom jail.d configuration at:", jailDFile)
	return nil
}

// writeFail2banAction creates or updates the action file with the AlertCountries.
func writeFail2banAction(alertCountries []string) error {

	// Join the alertCountries into a comma-separated string
	countriesFormatted := strings.Join(alertCountries, ",")

	// Define the Fail2Ban action file content
	actionConfig := fmt.Sprintf(`[INCLUDES]

before = sendmail-common.conf
         mail-whois-common.conf
         helpers-common.conf

[Definition]

# Bypass ban/unban for restored tickets
norestored = 1

# Option: actionban
# This executes the Python script with <ip> and the list of allowed countries.
# If the country matches the allowed list, it sends the email.
actionban = /etc/fail2ban/scripts/check_geoip.py <ip> "%s" && ( 
            printf %%%%b "Subject: [Fail2Ban] <name>: banned <ip> from <fq-hostname>
            Date: `+"`LC_ALL=C date +\"%%%%a, %%%%d %%%%h %%%%Y %%%%T %%%%z\"`"+`
            From: <sendername> <<sender>>
            To: <dest>\n
            Hi,\n
            The IP <ip> has just been banned by Fail2Ban after <failures> attempts against <name>.\n\n
            Here is more information about <ip>:\n"
            %%(_whois_command)s;
            printf %%%%b "\nLines containing failures of <ip> (max <grepmax>)\n";
            %%(_grep_logs)s;
            printf %%%%b "\n
            Regards,\n
            Fail2Ban" ) | <mailcmd>

[Init]

# Default name of the chain
name = default

# Path to log files containing relevant lines for the abuser IP
logpath = /dev/null

# Number of log lines to include in the email
# grepmax = 1000
# grepopts = -m <grepmax>
`, countriesFormatted)

	// Write the action file
	//actionFilePath := "/etc/fail2ban/action.d/ui-custom-action.conf"
	err := os.WriteFile(actionFile, []byte(actionConfig), 0644)
	if err != nil {
		return fmt.Errorf("failed to write action file: %w", err)
	}

	fmt.Printf("Action file successfully written to %s\n", actionFile)
	return nil
}

// loadSettings reads fail2ban-ui-settings.json into currentSettings.
func loadSettings() error {
	fmt.Println("----------------------------")
	fmt.Println("loadSettings called (settings.go)") // entry point
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
	fmt.Println("----------------------------")
	fmt.Println("saveSettings called (settings.go)") // entry point

	b, err := json.MarshalIndent(currentSettings, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling settings:", err) // Debug
		return err
	}
	fmt.Println("Settings marshaled, writing to file...") // Log marshaling success
	//return os.WriteFile(settingsFile, b, 0644)
	err = os.WriteFile(settingsFile, b, 0644)
	if err != nil {
		log.Println("Error writing to file:", err) // Debug
	} else {
		log.Println("Settings saved successfully!") // Debug
	}
	// Update the Fail2ban action file
	return writeFail2banAction(currentSettings.AlertCountries)
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

	fmt.Println("Locked settings for update") // Log lock acquisition

	old := currentSettings

	// If certain fields change, we mark reload needed
	if old.BantimeIncrement != new.BantimeIncrement ||
		old.IgnoreIP != new.IgnoreIP ||
		old.Bantime != new.Bantime ||
		old.Findtime != new.Findtime ||
		old.Maxretry != new.Maxretry ||
		old.Destemail != new.Destemail ||
		old.Sender != new.Sender {
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
	fmt.Println("New settings applied:", currentSettings) // Log settings applied

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
