package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// UISettings holds both the UI settings (like language) and
// relevant Fail2ban jail/local config options.
type UISettings struct {
	// UI-specific
	Language       string `json:"language"`
	// Whether a reload is needed (e.g. user changed filter or jail settings).
	ReloadNeeded   bool   `json:"reloadNeeded"`

	// These mirror some Fail2ban [DEFAULT] section parameters from jail.local
	BantimeIncrement bool   `json:"bantimeIncrement"`
	IgnoreIP         string `json:"ignoreip"`
	Bantime          string `json:"bantime"`
	Findtime         string `json:"findtime"`
	Maxretry         int    `json:"maxretry"`
	Destemail        string `json:"destemail"`
	Sender           string `json:"sender"`
}

// path to the JSON file (relative to where the app is started)
const settingsFile = "fail2ban-ui-settings.json"

// in-memory copy of settings
var (
	currentSettings UISettings
	settingsLock    sync.RWMutex
)

func init() {
	// Attempt to load existing file; if it doesn't exist, create with defaults.
	if err := loadSettings(); err != nil {
		fmt.Println("Error loading settings:", err)
		fmt.Println("Creating a new settings file with defaults...")

		// set defaults
		setDefaults()

		// save defaults to file
		if err := saveSettings(); err != nil {
			fmt.Println("Failed to save default settings:", err)
		}
	}
}

// setDefaults populates default values in currentSettings
func setDefaults() {
	settingsLock.Lock()
	defer settingsLock.Unlock()

	currentSettings = UISettings{
		Language:       "en",
		ReloadNeeded:   false,

		BantimeIncrement: true,
		IgnoreIP:         "127.0.0.1/8 ::1 172.16.10.1/24",
		Bantime:          "48h",
		Findtime:         "30m",
		Maxretry:         3,
		Destemail:        "admin@swissmakers.ch",
		Sender:           "noreply@swissmakers.ch",
	}
}

// loadSettings reads the file (if exists) into currentSettings
func loadSettings() error {
	data, err := os.ReadFile(settingsFile)
	if os.IsNotExist(err) {
		return err // triggers setDefaults + save
	}
	if err != nil {
		return err
	}

	var s UISettings
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
	settingsLock.RLock()
	defer settingsLock.RUnlock()

	b, err := json.MarshalIndent(currentSettings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(settingsFile, b, 0644)
}

// GetSettings returns a copy of the current settings
func GetSettings() UISettings {
	settingsLock.RLock()
	defer settingsLock.RUnlock()
	return currentSettings
}

// UpdateSettings modifies the in-memory settings, sets ReloadNeeded if required, then saves to disk.
// Optionally, we can detect changes that require a reload vs. changes that don't.
func UpdateSettings(new UISettings) (UISettings, error) {
	settingsLock.Lock()
	defer settingsLock.Unlock()

	// If user changed certain fields that require a Fail2ban reload, set ReloadNeeded = true.
	// For example, if any of these fields changed:
	reloadNeededBefore := currentSettings.ReloadNeeded

	if currentSettings.BantimeIncrement != new.BantimeIncrement ||
		currentSettings.IgnoreIP != new.IgnoreIP ||
		currentSettings.Bantime != new.Bantime ||
		currentSettings.Findtime != new.Findtime ||
		currentSettings.Maxretry != new.Maxretry ||
		currentSettings.Destemail != new.Destemail ||
		currentSettings.Sender != new.Sender {
		new.ReloadNeeded = true
	} else {
		// preserve previous ReloadNeeded if it was already true
		new.ReloadNeeded = new.ReloadNeeded || reloadNeededBefore
	}

	currentSettings = new

	// persist to file
	if err := saveSettings(); err != nil {
		return currentSettings, err
	}
	return currentSettings, nil
}

// MarkReloadDone sets ReloadNeeded = false after the user reloaded fail2ban
func MarkReloadDone() error {
	settingsLock.Lock()
	defer settingsLock.Unlock()
	currentSettings.ReloadNeeded = false
	return saveSettings()
}
