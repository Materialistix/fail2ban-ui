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

		// Routes for jail-filter management (TODO: rename API-call)
		api.GET("/jails/:jail/config", GetJailFilterConfigHandler)
		api.POST("/jails/:jail/config", SetJailFilterConfigHandler)

		// Routes for jail management
		api.GET("/jails/manage", ManageJailsHandler)
		api.POST("/jails/manage", UpdateJailManagementHandler)

		// Settings endpoints
		api.GET("/settings", GetSettingsHandler)
		api.POST("/settings", UpdateSettingsHandler)
		api.POST("/settings/test-email", TestEmailHandler)

		// Filter debugger endpoints
		api.GET("/filters", ListFiltersHandler)
		api.POST("/filters/test", TestFilterHandler)

		// TODO: create or generate new filters
		// api.POST("/filters/generate", GenerateFilterHandler)

		// Restart endpoint
		api.POST("/fail2ban/restart", RestartFail2banHandler)

		// Handle Fail2Ban notifications
		api.POST("/ban", BanNotificationHandler)
	}
}
