package utils

import (
	"strings"
)

// ParseUserMapping parses a list of "email:username" or "email=username" strings into a map of email -> username.
// Email keys are normalized to lowercase. Empty lines and comment lines (starting with #) are ignored.
func ParseUserMapping(mappings []string) map[string]string {
	result := make(map[string]string)
	for _, entry := range mappings {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		var email, username string
		if idx := strings.IndexAny(entry, ":="); idx != -1 {
			email = strings.TrimSpace(entry[:idx])
			username = strings.TrimSpace(entry[idx+1:])
		}
		if email != "" && username != "" {
			result[strings.ToLower(email)] = username
		}
	}
	return result
}
