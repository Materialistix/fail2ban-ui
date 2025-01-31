package main

import (
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/pkg/web"
)

func main() {
	settings := config.GetSettings()

	// Set Gin mode based on settings
	if settings.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()
	router.LoadHTMLGlob("pkg/web/templates/*") // Load HTML templates from pkg/web/templates
	web.RegisterRoutes(router)                 // Register routes (IndexHandler, /api/summary, jail/unban/:ip) etc..

	printWelcomeBanner()
	log.Println("--- Fail2Ban-UI started in", gin.Mode(), "mode ---")
	log.Println("Server listening on port :8080.")

	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Server crashed: %v", err)
	}
}

// printWelcomeBanner prints a cool Tux banner with startup info
func printWelcomeBanner() {
	greeting := getGreeting()
	const tuxBanner = `
      .--.
     |o_o |     %s
     |:_/ |
    //   \ \
   (|     | )
  /'\_   _/'\
  \___)=(___/

Fail2Ban UI - A Swissmade Management Interface
----------------------------------------------
Developers: https://swissmakers.ch
Mode: %s
Listening on: http://0.0.0.0:8080
----------------------------------------------

`
	fmt.Printf(tuxBanner, greeting, gin.Mode())
}

// getGreeting returns a friendly greeting based on the time of day
func getGreeting() string {
	hour := time.Now().Hour()
	switch {
	case hour < 12:
		return "Good morning!"
	case hour < 18:
		return "Good afternoon!"
	default:
		return "Good evening!"
	}
}
