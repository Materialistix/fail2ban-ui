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
		router.Static("/locales", "/app/locales")
	} else {
		// When running locally, load templates from pkg/web/templates
		router.LoadHTMLGlob("pkg/web/templates/*")
		router.Static("/locales", "./internal/locales")
	}

	// Register all application routes, including the static files and templates.
	web.RegisterRoutes(router)

	printWelcomeBanner(serverPort)
	log.Println("--- Fail2Ban-UI started in", gin.Mode(), "mode ---")
	log.Println("Server listening on port", serverPort, ".")

	// Start the server on port 8080.
	if err := router.Run(":" + serverPort); err != nil {
		log.Fatalf("Could not start server: %v\n", err)
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
