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

        // New config endpoints
        api.GET("/jails/:jail/config", GetJailConfigHandler)
        api.POST("/jails/:jail/config", SetJailConfigHandler)

        // Reload endpoint
        api.POST("/fail2ban/reload", ReloadFail2banHandler)
    }
}
