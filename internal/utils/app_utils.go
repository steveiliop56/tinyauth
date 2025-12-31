package utils

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/steveiliop56/tinyauth/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

// Get cookie domain parses a hostname and returns the upper domain (e.g. sub1.sub2.domain.com -> sub2.domain.com)
func GetCookieDomain(u string) (string, error) {
	parsed, err := url.Parse(u)
	if err != nil {
		return "", err
	}

	host := parsed.Hostname()

	if netIP := net.ParseIP(host); netIP != nil {
		return "", fmt.Errorf("IP addresses not allowed for app url '%s' (got IP: %s)", u, host)
	}

	parts := strings.Split(host, ".")

	if len(parts) < 3 {
		return "", fmt.Errorf("invalid app url '%s', must be at least second level domain (got %d parts, need 3+)", u, len(parts))
	}

	domain := strings.Join(parts[1:], ".")

	_, err = publicsuffix.DomainFromListWithOptions(publicsuffix.DefaultList, domain, nil)

	if err != nil {
		return "", fmt.Errorf("domain '%s' (from app url '%s') is in public suffix list, cannot set cookies", domain, u)
	}

	return domain, nil
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
	res = make([]T, 0)
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

	parsed, err := url.Parse(redirectURL)

	if err != nil {
		return false
	}

	hostname := parsed.Hostname()

	if strings.HasSuffix(hostname, domain) {
		return true
	}

	return hostname == domain
}
