package utils

import (
	"errors"
	"net/url"
	"strings"
	"tinyauth/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/traefik/paerser/parser"

	"github.com/rs/zerolog"
)

// Get upper domain parses a hostname and returns the upper domain (e.g. sub1.sub2.domain.com -> sub2.domain.com)
func GetUpperDomain(urlSrc string) (string, error) {
	urlParsed, err := url.Parse(urlSrc)
	if err != nil {
		return "", err
	}

	urlSplitted := strings.Split(urlParsed.Hostname(), ".")
	urlFinal := strings.Join(urlSplitted[1:], ".")

	return urlFinal, nil
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

func GetLabels(labels map[string]string) (config.Labels, error) {
	var labelsParsed config.Labels

	err := parser.Decode(labels, &labelsParsed, "tinyauth", "tinyauth.users", "tinyauth.allowed", "tinyauth.headers", "tinyauth.domain", "tinyauth.basic", "tinyauth.oauth", "tinyauth.ip")
	if err != nil {
		return config.Labels{}, err
	}

	return labelsParsed, nil
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

func GetLogLevel(level string) zerolog.Level {
	switch strings.ToLower(level) {
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
