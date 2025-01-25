package fail2ban

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	//"strings"
	"time"
)

var (
	// Typical fail2ban log line:
	//  2023-01-20 10:15:30,123 fail2ban.actions [1234]: NOTICE  [sshd] Ban 192.168.0.101
	logRegex = regexp.MustCompile(`^(\S+\s+\S+) fail2ban\.actions.*?\[\d+\]: NOTICE\s+\[(\S+)\]\s+Ban\s+(\S+)`)
)

// BanEvent holds details about a ban
type BanEvent struct {
	Time    time.Time
	Jail    string
	IP      string
	LogLine string
}

// ParseBanLog returns a map[jailName]BanEvents and also the last 5 ban events overall.
func ParseBanLog(logPath string) (map[string][]BanEvent, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open fail2ban log: %v", err)
	}
	defer file.Close()

	eventsByJail := make(map[string][]BanEvent)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		matches := logRegex.FindStringSubmatch(line)
		if len(matches) == 4 {
			// matches[1] -> "2023-01-20 10:15:30,123"
			// matches[2] -> jail name, e.g. "sshd"
			// matches[3] -> IP, e.g. "192.168.0.101"
			timestampStr := matches[1]
			jail := matches[2]
			ip := matches[3]

			// parse "2023-01-20 10:15:30,123" -> time.Time
			parsedTime, err := time.Parse("2006-01-02 15:04:05,000", timestampStr)
			if err != nil {
				// If parse fails, skip or set parsedTime=zero
				continue
			}

			ev := BanEvent{
				Time:    parsedTime,
				Jail:    jail,
				IP:      ip,
				LogLine: line,
			}

			eventsByJail[jail] = append(eventsByJail[jail], ev)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return eventsByJail, nil
}

// GetLastFiveBans crawls the parse results to find the last 5 ban events overall.
func GetLastFiveBans(eventsByJail map[string][]BanEvent) []BanEvent {
	var allEvents []BanEvent
	for _, events := range eventsByJail {
		allEvents = append(allEvents, events...)
	}

	// Sort by time descending
	// (We want the latest 5 ban events)
	sortByTimeDesc(allEvents)

	if len(allEvents) > 5 {
		return allEvents[:5]
	}
	return allEvents
}

// A simple in-file sorting utility
func sortByTimeDesc(events []BanEvent) {
	for i := 0; i < len(events); i++ {
		for j := i + 1; j < len(events); j++ {
			if events[j].Time.After(events[i].Time) {
				events[i], events[j] = events[j], events[i]
			}
		}
	}
}
