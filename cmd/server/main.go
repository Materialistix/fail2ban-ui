package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/internal/config"
	"github.com/swissmakers/fail2ban-ui/pkg/web"
)

func main() {
	// Get application settings from the config package.
	settings := config.GetSettings()

	// Set Gin mode based on the debug flag in settings.
	if settings.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create a new Gin router.
	router := gin.Default()
	serverPort := strconv.Itoa(int(settings.Port))

	// Load HTML templates depending on whether the application is running inside a container.
	_, container := os.LookupEnv("CONTAINER")
	if container {
		// In container, templates are assumed to be in /app/templates
		router.LoadHTMLGlob("/app/templates/*")
	} else {
		// When running locally, load templates from pkg/web/templates
		router.LoadHTMLGlob("pkg/web/templates/*")
	}

	// Register all application routes, including the static file serving route for locales.
	web.RegisterRoutes(router)

	printWelcomeBanner(serverPort)
	log.Println("--- Fail2Ban-UI started in", gin.Mode(), "mode ---")
	log.Println("Server listening on port", serverPort, ".")

	// Start the server on port 8080.
	if err := router.Run(":", serverPort); err != nil {
		log.Fatalf("Server crashed: %v", err)
	}
}

// printWelcomeBanner prints a cool Tux banner with startup info.
func printWelcomeBanner(appPort string) {
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
Developers:   https://swissmakers.ch
Mode:         %s
Listening on: http://0.0.0.0:%s
----------------------------------------------

`
	fmt.Printf(tuxBanner, greeting, gin.Mode(), appPort)
}

// getGreeting returns a friendly greeting based on the time of day.
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
