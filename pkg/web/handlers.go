package web

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/internal/fail2ban"
)

// SummaryResponse is what we return from /api/summary
type SummaryResponse struct {
	Jails    []fail2ban.JailInfo `json:"jails"`
	LastBans []fail2ban.BanEvent `json:"lastBans"`
}

// SummaryHandler returns a JSON summary of all jails, including
// number of banned IPs, how many are new in the last hour, etc.
// and the last 5 overall ban events from the log.
func SummaryHandler(c *gin.Context) {
	const logPath = "/var/log/fail2ban.log"

	jailInfos, err := fail2ban.BuildJailInfos(logPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Parse the log to find last 5 ban events
	eventsByJail, err := fail2ban.ParseBanLog(logPath)
	lastBans := make([]fail2ban.BanEvent, 0)
	if err == nil {
		// If we can parse logs successfully, let's gather all events
		var all []fail2ban.BanEvent
		for _, evs := range eventsByJail {
			all = append(all, evs...)
		}
		// Sort by descending time
		sortByTimeDesc(all)
		if len(all) > 5 {
			lastBans = all[:5]
		} else {
			lastBans = all
		}
	}

	resp := SummaryResponse{
		Jails:    jailInfos,
		LastBans: lastBans,
	}
	c.JSON(http.StatusOK, resp)
}

// UnbanIPHandler unbans a given IP in a specific jail.
func UnbanIPHandler(c *gin.Context) {
	fmt.Println("----------------------------")
	fmt.Println("UnbanIPHandler called (handlers.go)") // entry point
	jail := c.Param("jail")
	ip := c.Param("ip")

	err := fail2ban.UnbanIP(jail, ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	fmt.Println(ip + " from jail " + jail + " unbanned successfully (handlers.go)")
	c.JSON(http.StatusOK, gin.H{
		"message": "IP unbanned successfully",
	})
}

func sortByTimeDesc(events []fail2ban.BanEvent) {
	for i := 0; i < len(events); i++ {
		for j := i + 1; j < len(events); j++ {
			if events[j].Time.After(events[i].Time) {
				events[i], events[j] = events[j], events[i]
			}
		}
	}
}

// IndexHandler serves the HTML page
func IndexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"timestamp": time.Now().Format(time.RFC1123),
	})
}

// GetJailFilterConfigHandler returns the raw filter config for a given jail
func GetJailFilterConfigHandler(c *gin.Context) {
	fmt.Println("----------------------------")
	fmt.Println("GetJailFilterConfigHandler called (handlers.go)") // entry point
	jail := c.Param("jail")
	cfg, err := fail2ban.GetJailConfig(jail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"jail":   jail,
		"config": cfg,
	})
}

// SetJailFilterConfigHandler overwrites the current filter config with new content
func SetJailFilterConfigHandler(c *gin.Context) {
	fmt.Println("----------------------------")
	fmt.Println("SetJailFilterConfigHandler called (handlers.go)") // entry point
	jail := c.Param("jail")

	// Parse JSON body (containing the new filter content)
	var req struct {
		Config string `json:"config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}

	// Write the filter config file to /etc/fail2ban/filter.d/<jail>.conf
	if err := fail2ban.SetJailConfig(jail, req.Config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Mark reload needed in our UI settings
	//	if err := config.MarkReloadNeeded(); err != nil {
	//		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	//		return
	//	}

	c.JSON(http.StatusOK, gin.H{"message": "jail config updated"})

	// Return a simple JSON response without forcing a blocking alert
	//	c.JSON(http.StatusOK, gin.H{
	//		"message":      "Filter updated, reload needed",
	//		"reloadNeeded": true,
	//	})
}

// GetSettingsHandler returns the entire AppSettings struct as JSON
func GetSettingsHandler(c *gin.Context) {
	fmt.Println("----------------------------")
	fmt.Println("GetSettingsHandler called (handlers.go)") // entry point
	s := config.GetSettings()
	c.JSON(http.StatusOK, s)
}

// UpdateSettingsHandler updates the AppSettings from a JSON body
func UpdateSettingsHandler(c *gin.Context) {
	fmt.Println("----------------------------")
	fmt.Println("UpdateSettingsHandler called (handlers.go)") // entry point
	var req config.AppSettings
	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Println("JSON binding error:", err) // Debug
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid JSON",
			"details": err.Error(),
		})
		return
	}
	fmt.Println("JSON binding successful, updating settings (handlers.go)")

	newSettings, err := config.UpdateSettings(req)
	if err != nil {
		fmt.Println("Error updating settings:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	fmt.Println("Settings updated successfully (handlers.go)")

	c.JSON(http.StatusOK, gin.H{
		"message":      "Settings updated",
		"reloadNeeded": newSettings.ReloadNeeded,
	})
}

// ListFiltersHandler returns a JSON array of filter names
// found as *.conf in /etc/fail2ban/filter.d
func ListFiltersHandler(c *gin.Context) {
	fmt.Println("----------------------------")
	fmt.Println("ListFiltersHandler called (handlers.go)") // entry point
	dir := "/etc/fail2ban/filter.d"

	files, err := os.ReadDir(dir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to read filter directory: " + err.Error(),
		})
		return
	}

	var filters []string
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".conf") {
			name := strings.TrimSuffix(f.Name(), ".conf")
			filters = append(filters, name)
		}
	}

	c.JSON(http.StatusOK, gin.H{"filters": filters})
}

func TestFilterHandler(c *gin.Context) {
	fmt.Println("----------------------------")
	fmt.Println("TestFilterHandler called (handlers.go)") // entry point
	var req struct {
		FilterName string   `json:"filterName"`
		LogLines   []string `json:"logLines"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	// For now, just pretend nothing matches
	c.JSON(http.StatusOK, gin.H{"matches": []string{}})
}

// ApplyFail2banSettings updates /etc/fail2ban/jail.local [DEFAULT] with our JSON
func ApplyFail2banSettings(jailLocalPath string) error {
	fmt.Println("----------------------------")
	fmt.Println("ApplyFail2banSettings called (handlers.go)") // entry point
	s := config.GetSettings()

	// open /etc/fail2ban/jail.local, parse or do a simplistic approach:
	// TODO: -> maybe we store [DEFAULT] block in memory, replace lines
	// or do a line-based approach. Example is simplistic:

	newLines := []string{
		"[DEFAULT]",
		fmt.Sprintf("bantime.increment = %t", s.BantimeIncrement),
		fmt.Sprintf("ignoreip = %s", s.IgnoreIP),
		fmt.Sprintf("bantime = %s", s.Bantime),
		fmt.Sprintf("findtime = %s", s.Findtime),
		fmt.Sprintf("maxretry = %d", s.Maxretry),
		fmt.Sprintf("destemail = %s", s.Destemail),
		fmt.Sprintf("sender = %s", s.Sender),
		"",
	}
	content := strings.Join(newLines, "\n")

	return os.WriteFile(jailLocalPath, []byte(content), 0644)
}

// ReloadFail2banHandler reloads the Fail2ban service
func ReloadFail2banHandler(c *gin.Context) {
	fmt.Println("----------------------------")
	fmt.Println("ApplyFail2banSettings called (handlers.go)") // entry point

	// First we write our new settings to /etc/fail2ban/jail.local
	//	if err := fail2ban.ApplyFail2banSettings("/etc/fail2ban/jail.local"); err != nil {
	//		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	//		return
	//	}

	// Then reload
	if err := fail2ban.ReloadFail2ban(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// We set reload done in config
	if err := config.MarkReloadDone(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Fail2ban reloaded successfully"})
}
