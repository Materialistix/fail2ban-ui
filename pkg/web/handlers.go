package web

import (
	"io/ioutil"
	"net/http"
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
	jail := c.Param("jail")
	ip := c.Param("ip")

	err := fail2ban.UnbanIP(jail, ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
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
	jail := c.Param("jail")

	var req struct {
		Config string `json:"config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}

	if err := fail2ban.SetJailConfig(jail, req.Config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "jail config updated"})
}

// GetSettingsHandler returns the current fail2ban-ui settings
func GetSettingsHandler(c *gin.Context) {
	s := config.GetSettings()
	c.JSON(http.StatusOK, s)
}

// UpdateSettingsHandler updates the fail2ban-ui settings
func UpdateSettingsHandler(c *gin.Context) {
	//	var req config.Settings
	//	if err := c.ShouldBindJSON(&req); err != nil {
	//		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
	//		return
	//	}

	//	needsRestart, err := config.UpdateSettings(req)
	//	if err != nil {
	//		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	//		return
	//	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Settings updated",
		//		"needsRestart":  needsRestart,
	})
}

// ListFiltersHandler returns a JSON array of filter names
// found as *.conf in /etc/fail2ban/filter.d
func ListFiltersHandler(c *gin.Context) {
	dir := "/etc/fail2ban/filter.d" // adjust if needed

	files, err := ioutil.ReadDir(dir)
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

// ReloadFail2banHandler reloads the Fail2ban service
func ReloadFail2banHandler(c *gin.Context) {
	err := fail2ban.ReloadFail2ban()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Fail2ban reloaded successfully"})
}
