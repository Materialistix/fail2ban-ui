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

package config

import (
	"log"
)

// DebugLog prints debug messages only if debug mode is enabled.
func DebugLog(format string, v ...interface{}) {
	// Avoid deadlocks by not calling GetSettings() inside DebugLog.
	debugEnabled := false
	debugEnabled = currentSettings.Debug
	if !debugEnabled {
		return
	}
	// Ensure correct usage of fmt.Printf-style formatting
	if len(v) > 0 {
		log.Printf(format, v...) // Uses format directives
	} else {
		log.Println(format) // Just prints the message
	}
}
