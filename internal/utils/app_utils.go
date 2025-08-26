package utils

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"tinyauth/internal/config"

	"github.com/gin-gonic/gin"

	"github.com/rs/zerolog"
)

// Get upper domain parses a hostname and returns the upper domain (e.g. sub1.sub2.domain.com -> sub2.domain.com)
func GetUpperDomain(appUrl string) (string, error) {
	appUrlParsed, err := url.Parse(appUrl)
	if err != nil {
		return "", err
	}

	host := appUrlParsed.Hostname()

	if netIP := net.ParseIP(host); netIP != nil {
		return "", errors.New("IP addresses are not allowed")
	}

	urlParts := strings.Split(host, ".")

	if len(urlParts) < 2 {
		return "", errors.New("invalid domain, must be at least second level domain")
	}

	return strings.Join(urlParts[1:], "."), nil
}

func ParseFileToLine(content string) string {
	lines := strings.Split(content, "\n")
	users := make([]string, 0)

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		users = append(users, strings.TrimSpace(line))
	}

	return strings.Join(users, ",")
}

func Filter[T any](slice []T, test func(T) bool) (res []T) {
	for _, value := range slice {
		if test(value) {
			res = append(res, value)
		}
	}
	return res
}

func GetContext(c *gin.Context) (config.UserContext, error) {
	userContextValue, exists := c.Get("context")

	if !exists {
		return config.UserContext{}, errors.New("no user context in request")
	}

	userContext, ok := userContextValue.(*config.UserContext)

	if !ok {
		return config.UserContext{}, errors.New("invalid user context in request")
	}

	return *userContext, nil
}

func IsRedirectSafe(redirectURL string, domain string) bool {
	if redirectURL == "" {
		return false
	}

	parsedURL, err := url.Parse(redirectURL)

	if err != nil {
		return false
	}

	if !parsedURL.IsAbs() {
		return false
	}

	upper, err := GetUpperDomain(redirectURL)

	if err != nil {
		return false
	}

	if upper != domain {
		return false
	}

	return true
}

func GetLogLevel(level string) zerolog.Level {
	switch strings.ToLower(level) {
	case "trace":
		return zerolog.TraceLevel
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	case "panic":
		return zerolog.PanicLevel
	default:
		return zerolog.InfoLevel
	}
}
