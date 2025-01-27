package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
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

// path to the JSON file (relative to where the app is started)
const settingsFile = "fail2ban-ui-settings.json"

// in-memory copy of settings
var (
	currentSettings AppSettings
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

	currentSettings = AppSettings{
		Language:       "en",
		Debug:          false,
		ReloadNeeded:   false,
		AlertCountries: []string{"all"},

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
	return nil
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
