package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/swissmakers/fail2ban-ui/pkg/web"
)

func main() {
	r := gin.Default()

	// Load HTML templates from pkg/web/templates
	r.LoadHTMLGlob("pkg/web/templates/*")

	// Register our routes (IndexHandler, /api/summary, /api/jails/:jail/unban/:ip)
	web.RegisterRoutes(r)

	log.Println("Starting Fail2ban-UI server on :8080.")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Server crashed: %v", err)
	}
}
