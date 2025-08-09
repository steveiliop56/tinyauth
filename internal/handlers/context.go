package handlers

import (
	"net/url"
	"os"
	"strings"
	"tinyauth/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// extractDomainFromURL extracts the domain from a URL string
func extractDomainFromURL(urlStr string) string {
	if urlStr == "" {
		return ""
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}

	return parsedURL.Host
}

// getDomainFromRequest attempts to get the requesting domain from redirect_uri or referer
func getDomainFromRequest(c *gin.Context) string {
	// First try redirect_uri from query parameter
	redirectURI := c.Query("redirect_uri")
	if domain := extractDomainFromURL(redirectURI); domain != "" {
		return domain
	}

	// Try redirect_uri from session cookie (for when user is already on login page)
	if cookie, err := c.Cookie("redirect_uri"); err == nil && cookie != "" {
		if domain := extractDomainFromURL(cookie); domain != "" {
			return domain
		}
	}

	// Try to extract redirect_uri from referer if it contains it (e.g., /login?redirect_uri=...)
	referer := c.GetHeader("Referer")
	if referer != "" {
		// Check if referer is a login page with redirect_uri parameter
		if parsedReferer, err := url.Parse(referer); err == nil {
			if redirectURIFromReferer := parsedReferer.Query().Get("redirect_uri"); redirectURIFromReferer != "" {
				if domain := extractDomainFromURL(redirectURIFromReferer); domain != "" {
					return domain
				}
			}
		}

		// Fall back to referer domain itself
		if domain := extractDomainFromURL(referer); domain != "" {
			return domain
		}
	}

	return ""
}

// getDomainBranding gets domain-specific branding from environment variables
func getDomainBranding(domain, brandingKey, fallbackValue string) string {
	if domain == "" {
		return fallbackValue
	}

	// Try domain-specific branding: BRANDING_domain.com_KEY
	envKey := "BRANDING_" + strings.ReplaceAll(domain, ".", "_") + "_" + brandingKey
	if value := os.Getenv(envKey); value != "" {
		return value
	}

	// Try simplified domain branding: BRANDING_domain_KEY (without TLD)
	domainParts := strings.Split(domain, ".")
	if len(domainParts) > 1 {
		simpleDomain := domainParts[0]
		envKey = "BRANDING_" + simpleDomain + "_" + brandingKey
		if value := os.Getenv(envKey); value != "" {
			return value
		}
	}

	return fallbackValue
}

func (h *Handlers) AppContextHandler(c *gin.Context) {
	log.Debug().Msg("Getting app context")

	// Get configured providers
	configuredProviders := h.Providers.GetConfiguredProviders()

	// We have username/password configured so add it to our providers
	if h.Auth.UserAuthConfigured() {
		configuredProviders = append(configuredProviders, "username")
	}

	// Get the domain from request (redirect_uri, referer, etc.)
	requestDomain := getDomainFromRequest(c)

	// Apply domain-specific branding with fallback to config defaults
title := getDomainBranding(requestDomain, "TITLE", h.Config.Title)
loginTitle := getDomainBranding(requestDomain, "LOGIN_TITLE", h.Config.LoginTitle)
loginSubtitle := getDomainBranding(requestDomain, "LOGIN_SUBTITLE", h.Config.LoginSubtitle)
logo := getDomainBranding(requestDomain, "LOGO", h.Config.Logo)
backgroundImage := getDomainBranding(requestDomain, "BACKGROUND_IMAGE", h.Config.BackgroundImage)
	usernameTitle := getDomainBranding(requestDomain, "USERNAME_TITLE", h.Config.UsernameTitle)
	passwordTitle := getDomainBranding(requestDomain, "PASSWORD_TITLE", h.Config.PasswordTitle)
	usernamePlaceholder := getDomainBranding(requestDomain, "USERNAME_PLACEHOLDER", h.Config.UsernamePlaceholder)
	passwordPlaceholder := getDomainBranding(requestDomain, "PASSWORD_PLACEHOLDER", h.Config.PasswordPlaceholder)
	forgotPasswordMessage := getDomainBranding(requestDomain, "FORGOT_PASSWORD_MESSAGE", h.Config.ForgotPasswordMessage)

	// Log dynamic branding detection
	if requestDomain != "" {
		log.Debug().
			Str("request_domain", requestDomain).
			Str("app_title", title).
			Str("login_title", loginTitle).
			Str("logo", logo).
			Msg("Dynamic branding detected from domain")
	}

	// Return app context with dynamic branding
	appContext := types.AppContext{
		Status:                200,
		Message:               "OK",
		ConfiguredProviders:   configuredProviders,
		DisableContinue:       h.Config.DisableContinue,
		Title:                 title,
		GenericName:           h.Config.GenericName,
		Domain:                h.Config.Domain,
		ForgotPasswordMessage: forgotPasswordMessage,
		BackgroundImage:       backgroundImage,
		LoginTitle:            loginTitle,
		LoginSubtitle:         loginSubtitle,
		UsernameTitle:         usernameTitle,
		PasswordTitle:         passwordTitle,
		UsernamePlaceholder:   usernamePlaceholder,
		PasswordPlaceholder:   passwordPlaceholder,
		Logo:                  logo,
		OAuthAutoRedirect:     h.Config.OAuthAutoRedirect,
	}
	c.JSON(200, appContext)
}

func (h *Handlers) UserContextHandler(c *gin.Context) {
	log.Debug().Msg("Getting user context")

	// Create user context using hooks
	userContext := h.Hooks.UseUserContext(c)

	userContextResponse := types.UserContextResponse{
		Status:      200,
		IsLoggedIn:  userContext.IsLoggedIn,
		Username:    userContext.Username,
		Name:        userContext.Name,
		Email:       userContext.Email,
		Provider:    userContext.Provider,
		Oauth:       userContext.OAuth,
		TotpPending: userContext.TotpPending,
	}

	// If we are not logged in we set the status to 401 else we set it to 200
	if !userContext.IsLoggedIn {
		log.Debug().Msg("Unauthorized")
		userContextResponse.Message = "Unauthorized"
	} else {
		log.Debug().Interface("userContext", userContext).Msg("Authenticated")
		userContextResponse.Message = "Authenticated"
	}

	c.JSON(200, userContextResponse)
}
