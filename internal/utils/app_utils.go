package utils

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"tinyauth/internal/config"
	"tinyauth/internal/utils/decoders"

	"maps"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
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
		return "", errors.New("IP addresses not allowed")
	}

	parts := strings.Split(host, ".")

	if len(parts) < 3 {
		return "", errors.New("invalid app url, must be at least second level domain")
	}

	domain := strings.Join(parts[1:], ".")

	_, err = publicsuffix.DomainFromListWithOptions(publicsuffix.DefaultList, domain, nil)

	if err != nil {
		return "", errors.New("domain in public suffix list, cannot set cookies")
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

	parsedURL, err := url.Parse(redirectURL)

	if err != nil {
		return false
	}

	if !parsedURL.IsAbs() {
		return false
	}

	host := parsedURL.Hostname()
	if host == domain {
		return true
	}

	cookieDomain, err := GetCookieDomain(redirectURL)
	if err != nil {
		return false
	}

	return cookieDomain == domain
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

func GetOAuthProvidersConfig(environ []string, args []string, appUrl string) (map[string]config.OAuthServiceConfig, error) {
	providers := make(map[string]config.OAuthServiceConfig)

	// Get from environment variables
	envProviders, err := decoders.DecodeEnv[config.Providers](environ)

	if err != nil {
		return nil, err
	}

	maps.Copy(providers, envProviders.Providers)

	// Get from args
	argProviders, err := decoders.DecodeFlags[config.Providers](args)

	if err != nil {
		return nil, err
	}

	maps.Copy(providers, argProviders.Providers)

	// For every provider get correct secret from file if set
	for name, provider := range providers {
		secret := GetSecret(provider.ClientSecret, provider.ClientSecretFile)
		provider.ClientSecret = secret
		provider.ClientSecretFile = ""
		providers[name] = provider
	}

	// If we have google/github providers and no redirect URL then set a default
	for id := range config.OverrideProviders {
		if provider, exists := providers[id]; exists {
			if provider.RedirectURL == "" {
				provider.RedirectURL = appUrl + "/api/oauth/callback/" + id
				providers[id] = provider
			}
		}
	}

	// Set names
	for id, provider := range providers {
		if provider.Name == "" {
			if name, ok := config.OverrideProviders[id]; ok {
				provider.Name = name
			} else {
				provider.Name = Capitalize(id)
			}
		}
		providers[id] = provider
	}

	// Return combined providers
	return providers, nil
}

func GetACLS(environ []string, args []string) (config.Apps, error) {
	acls := config.Apps{}
	acls.Apps = make(map[string]config.App)

	// Get from environment variables
	envACLs, err := decoders.DecodeEnv[config.Apps](environ)

	if err != nil {
		return config.Apps{}, err
	}

	maps.Copy(acls.Apps, envACLs.Apps)

	// Get from args
	argACLs, err := decoders.DecodeFlags[config.Apps](args)

	if err != nil {
		return config.Apps{}, err
	}

	maps.Copy(acls.Apps, argACLs.Apps)

	return acls, nil
}
