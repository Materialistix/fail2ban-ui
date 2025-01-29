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

package fail2ban

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type JailInfo struct {
	JailName      string   `json:"jailName"`
	TotalBanned   int      `json:"totalBanned"`
	NewInLastHour int      `json:"newInLastHour"`
	BannedIPs     []string `json:"bannedIPs"`
}

// GetJails returns all configured jails using "fail2ban-client status".
func GetJails() ([]string, error) {
	cmd := exec.Command("fail2ban-client", "status")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("could not get jail information. is fail2ban running? error: %v", err)
	}

	var jails []string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Jail list:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				raw := strings.TrimSpace(parts[1])
				jails = strings.Split(raw, ",")
				for i := range jails {
					jails[i] = strings.TrimSpace(jails[i])
				}
			}
		}
	}
	return jails, nil
}

// GetBannedIPs returns a slice of currently banned IPs for a specific jail.
func GetBannedIPs(jail string) ([]string, error) {
	cmd := exec.Command("fail2ban-client", "status", jail)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("fail2ban-client status %s failed: %v", jail, err)
	}

	var bannedIPs []string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "IP list:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				ips := strings.Fields(strings.TrimSpace(parts[1]))
				bannedIPs = append(bannedIPs, ips...)
			}
			break
		}
	}
	return bannedIPs, nil
}

// UnbanIP unbans an IP from the given jail.
func UnbanIP(jail, ip string) error {
	// We assume "fail2ban-client set <jail> unbanip <ip>" works.
	cmd := exec.Command("fail2ban-client", "set", jail, "unbanip", ip)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error unbanning IP %s from jail %s: %v\nOutput: %s", ip, jail, err, out)
	}
	return nil
}

// BuildJailInfos returns extended info for each jail:
// - total banned count
// - new banned in the last hour
// - list of currently banned IPs
func BuildJailInfos(logPath string) ([]JailInfo, error) {
	jails, err := GetJails()
	if err != nil {
		return nil, err
	}

	// Parse the log once, so we can determine "newInLastHour" per jail
	// for performance reasons. We'll gather all ban timestamps by jail.
	banHistory, err := ParseBanLog(logPath)
	if err != nil {
		// If fail2ban.log can't be read, we can still show partial info.
		banHistory = make(map[string][]BanEvent)
	}

	oneHourAgo := time.Now().Add(-1 * time.Hour)

	var results []JailInfo
	for _, jail := range jails {
		bannedIPs, err := GetBannedIPs(jail)
		if err != nil {
			// Just skip or handle error per jail
			continue
		}

		// Count how many bans occurred in the last hour for this jail
		newInLastHour := 0
		if events, ok := banHistory[jail]; ok {
			for _, e := range events {
				if e.Time.After(oneHourAgo) {
					newInLastHour++
				}
			}
		}

		jinfo := JailInfo{
			JailName:      jail,
			TotalBanned:   len(bannedIPs),
			NewInLastHour: newInLastHour,
			BannedIPs:     bannedIPs,
		}
		results = append(results, jinfo)
	}
	return results, nil
}

// GetJailConfig returns the config content for a given jail.
// Example: we assume each jail config is at /etc/fail2ban/filter.d/<jail>.conf
// Adapt this to your environment.
func GetJailConfig(jail string) (string, error) {
	configPath := filepath.Join("/etc/fail2ban/filter.d", jail+".conf")
	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read config for jail %s: %v", jail, err)
	}
	return string(content), nil
}

// SetJailConfig overwrites the config file for a given jail with new content.
func SetJailConfig(jail, newContent string) error {
	configPath := filepath.Join("/etc/fail2ban/filter.d", jail+".conf")
	if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write config for jail %s: %v", jail, err)
	}
	return nil
}

// ReloadFail2ban runs "fail2ban-client reload"
func ReloadFail2ban() error {
	cmd := exec.Command("fail2ban-client", "reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("fail2ban reload error: %v\nOutput: %s", err, out)
	}
	return nil
}
