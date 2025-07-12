package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/rs/zerolog/log"
)

func (h *Handlers) OAuthURLHandler(c *gin.Context) {
	var request types.OAuthRequest

	err := c.BindUri(&request)
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	log.Debug().Msg("Got OAuth request")

	// Check if provider exists
	provider := h.Providers.GetProvider(request.Provider)

	if provider == nil {
		c.JSON(404, gin.H{
			"status":  404,
			"message": "Not Found",
		})
		return
	}

	log.Debug().Str("provider", request.Provider).Msg("Got provider")

	// Create state
	state := provider.GenerateState()

	// Get auth URL
	authURL := provider.GetAuthURL(state)

	log.Debug().Msg("Got auth URL")

	// Set CSRF cookie
	c.SetCookie(h.Config.CsrfCookieName, state, int(time.Hour.Seconds()), "/", "", h.Config.CookieSecure, true)

	// Get redirect URI
	redirectURI := c.Query("redirect_uri")

	// Set redirect cookie if redirect URI is provided
	if redirectURI != "" {
		log.Debug().Str("redirectURI", redirectURI).Msg("Setting redirect cookie")
		c.SetCookie(h.Config.RedirectCookieName, redirectURI, int(time.Hour.Seconds()), "/", "", h.Config.CookieSecure, true)
	}

	// Return auth URL
	c.JSON(200, gin.H{
		"status":  200,
		"message": "OK",
		"url":     authURL,
	})
}

func (h *Handlers) OAuthCallbackHandler(c *gin.Context) {
	var providerName types.OAuthRequest

	err := c.BindUri(&providerName)
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind URI")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	log.Debug().Interface("provider", providerName.Provider).Msg("Got provider name")

	// Get state
	state := c.Query("state")

	// Get CSRF cookie
	csrfCookie, err := c.Cookie(h.Config.CsrfCookieName)

	if err != nil {
		log.Debug().Msg("No CSRF cookie")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	log.Debug().Str("csrfCookie", csrfCookie).Msg("Got CSRF cookie")

	// Check if CSRF cookie is valid
	if csrfCookie != state {
		log.Warn().Msg("Invalid CSRF cookie or CSRF cookie does not match with the state")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	// Clean up CSRF cookie
	c.SetCookie(h.Config.CsrfCookieName, "", -1, "/", "", h.Config.CookieSecure, true)

	// Get code
	code := c.Query("code")

	log.Debug().Msg("Got code")

	// Get provider
	provider := h.Providers.GetProvider(providerName.Provider)

	if provider == nil {
		c.Redirect(http.StatusTemporaryRedirect, "/not-found")
		return
	}

	log.Debug().Str("provider", providerName.Provider).Msg("Got provider")

	// Exchange token (authenticates user)
	_, err = provider.ExchangeToken(code)
	if err != nil {
		log.Error().Err(err).Msg("Failed to exchange token")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	log.Debug().Msg("Got token")

	// Get user
	user, err := h.Providers.GetUser(providerName.Provider)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get user")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	log.Debug().Msg("Got user")

	// Check that email is not empty
	if user.Email == "" {
		log.Error().Msg("Email is empty")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	// Email is not whitelisted
	if !h.Auth.EmailWhitelisted(user.Email) {
		log.Warn().Str("email", user.Email).Msg("Email not whitelisted")
		queries, err := query.Values(types.UnauthorizedQuery{
			Username: user.Email,
		})

		if err != nil {
			log.Error().Err(err).Msg("Failed to build queries")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
	}

	log.Debug().Msg("Email whitelisted")

	// Get username
	var username string

	if user.PreferredUsername != "" {
		username = user.PreferredUsername
	} else {
		username = fmt.Sprintf("%s_%s", strings.Split(user.Email, "@")[0], strings.Split(user.Email, "@")[1])
	}

	// Get name
	var name string

	if user.Name != "" {
		name = user.Name
	} else {
		name = fmt.Sprintf("%s (%s)", utils.Capitalize(strings.Split(user.Email, "@")[0]), strings.Split(user.Email, "@")[1])
	}

	// Create session cookie
	h.Auth.CreateSessionCookie(c, &types.SessionCookie{
		Username:    username,
		Name:        name,
		Email:       user.Email,
		Provider:    providerName.Provider,
		OAuthGroups: strings.Join(user.Groups, ","),
	})

	// Check if we have a redirect URI
	redirectCookie, err := c.Cookie(h.Config.RedirectCookieName)

	if err != nil {
		log.Debug().Msg("No redirect cookie")
		c.Redirect(http.StatusTemporaryRedirect, h.Config.AppURL)
		return
	}

	log.Debug().Str("redirectURI", redirectCookie).Msg("Got redirect URI")

	queries, err := query.Values(types.LoginQuery{
		RedirectURI: redirectCookie,
	})

	if err != nil {
		log.Error().Err(err).Msg("Failed to build queries")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	log.Debug().Msg("Got redirect query")

	// Clean up redirect cookie
	c.SetCookie(h.Config.RedirectCookieName, "", -1, "/", "", h.Config.CookieSecure, true)

	// Redirect to continue with the redirect URI
	c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/continue?%s", h.Config.AppURL, queries.Encode()))
}
