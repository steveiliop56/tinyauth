package utils

import (
	"strings"
	"tinyauth/internal/config"

	"github.com/traefik/paerser/parser"
)

func GetLabels(labels map[string]string) (config.Labels, error) {
	var labelsParsed config.Labels

	err := parser.Decode(labels, &labelsParsed, "tinyauth", "tinyauth.users", "tinyauth.allowed", "tinyauth.headers", "tinyauth.domain", "tinyauth.basic", "tinyauth.oauth", "tinyauth.ip")
	if err != nil {
		return config.Labels{}, err
	}

	return labelsParsed, nil
}

func ParseHeaders(headers []string) map[string]string {
	headerMap := make(map[string]string)
	for _, header := range headers {
		split := strings.SplitN(header, "=", 2)
		if len(split) != 2 || strings.TrimSpace(split[0]) == "" || strings.TrimSpace(split[1]) == "" {
			continue
		}
		key := SanitizeHeader(strings.TrimSpace(split[0]))
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
