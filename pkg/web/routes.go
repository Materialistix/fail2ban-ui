package web

import (
	"github.com/gin-gonic/gin"
)

// RegisterRoutes sets up the routes for the Fail2ban UI.
func RegisterRoutes(r *gin.Engine) {
	// Render the dashboard
	r.GET("/", IndexHandler)

	api := r.Group("/api")
	{
		api.GET("/summary", SummaryHandler)
		api.POST("/jails/:jail/unban/:ip", UnbanIPHandler)

		// config endpoints
		api.GET("/jails/:jail/config", GetJailFilterConfigHandler)
		api.POST("/jails/:jail/config", SetJailFilterConfigHandler)

		// settings
		api.GET("/settings", GetSettingsHandler)
		api.POST("/settings", UpdateSettingsHandler)

		// filter debugger
		api.GET("/filters", ListFiltersHandler)
		api.POST("/filters/test", TestFilterHandler)
		// TODO create or generate new filters
		// api.POST("/filters/generate", GenerateFilterHandler)

		// Reload endpoint
		api.POST("/fail2ban/reload", ReloadFail2banHandler)
	}
}
