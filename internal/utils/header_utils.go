package utils

import (
	"net/http"
	"strings"
)

func ParseHeaders(headers []string) map[string]string {
	headerMap := make(map[string]string)
	for _, header := range headers {
		split := strings.SplitN(header, "=", 2)
		if len(split) != 2 || strings.TrimSpace(split[0]) == "" || strings.TrimSpace(split[1]) == "" {
			continue
		}
		key := SanitizeHeader(strings.TrimSpace(split[0]))
		if strings.ContainsAny(key, " \t") {
			continue
		}
		key = http.CanonicalHeaderKey(key)
		value := SanitizeHeader(strings.TrimSpace(split[1]))
		headerMap[key] = value
	}
	return headerMap
}

func SanitizeHeader(header string) string {
	return strings.Map(func(r rune) rune {
		// Allow only printable ASCII characters (32-126) and safe whitespace (space, tab)
		if r == ' ' || r == '\t' || (r >= 32 && r <= 126) {
			return r
		}
		return -1
	}, header)
}

func NormalizeHeaders(headers http.Header) map[string]string {
	var result = make(map[string]string)

	for key, values := range headers {
		result[key] = strings.Join(values, ",")
	}

	return result
}
