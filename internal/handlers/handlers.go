package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"tinyauth/internal/auth"
	"tinyauth/internal/hooks"
	"tinyauth/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/rs/zerolog/log"
)

func NewHandlers(config types.APIConfig, auth *auth.Auth, hooks *hooks.Hooks) *Handlers {
	return &Handlers{
		Config: config,
		Auth:   auth,
		Hooks:  hooks,
	}
}

type Handlers struct {
	Config types.APIConfig
	Auth   *auth.Auth
	Hooks  *hooks.Hooks
}

// @Summary Health Check
// @Description Simple health check
// @Tags health
// @Produce  json
// @Success 200 {object} types.HealthCheckResponse
// @Router /healthcheck [get]
func (h *Handlers) HealthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  200,
		"message": "OK",
	})
}

// @Summary Logout
// @Description Log the user out by invalidating the session cookie
// @Tags auth
// @Produce  json
// @Success 200 {object} types.LogoutResponse
// @Router /auth/logout [get]
func (h *Handlers) Logout(c *gin.Context) {
	log.Debug().Msg("Logging out")

	h.Auth.DeleteSessionCookie(c)

	log.Debug().Msg("Cleaning up redirect cookie")

	c.SetCookie("tinyauth_redirect_uri", "", -1, "/", h.Config.Domain, h.Config.CookieSecure, true)

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Logged out",
	})
}

// @Summary Auth Check (Traefik)
// @Description Check the authentication status of the user and redirect to the login page if not authenticated
// @Tags authn
// @Produce  json
// @Success 302
// @Router /api/auth/traefik [get]
func (h *Handlers) CheckAuth(c *gin.Context) {
	var proxy types.Proxy

	err := c.BindUri(&proxy)

	if err != nil {
		log.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	isBrowser := strings.Contains(c.Request.Header.Get("Accept"), "text/html")

	if isBrowser {
		log.Debug().Msg("Request is most likely coming from a browser")
	} else {
		log.Debug().Msg("Request is most likely not coming from a browser")
	}

	log.Debug().Interface("proxy", proxy.Proxy).Msg("Got proxy")

	authEnabled, err := h.Auth.AuthEnabled(c)

	if err != nil {
		log.Error().Err(err).Msg("Failed to check if auth is enabled")

		if proxy.Proxy == "nginx" || !isBrowser {
			c.JSON(500, gin.H{
				"status":  500,
				"message": "Internal Server Error",
			})
			return
		}

		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	if !authEnabled {
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	userContext := h.Hooks.UseUserContext(c)

	uri := c.Request.Header.Get("X-Forwarded-Uri")
	proto := c.Request.Header.Get("X-Forwarded-Proto")
	host := c.Request.Header.Get("X-Forwarded-Host")

	if userContext.IsLoggedIn {
		log.Debug().Msg("Authenticated")

		appAllowed, err := h.Auth.ResourceAllowed(c, userContext)

		if err != nil {
			log.Error().Err(err).Msg("Failed to check if app is allowed")

			if proxy.Proxy == "nginx" || !isBrowser {
				c.JSON(500, gin.H{
					"status":  500,
					"message": "Internal Server Error",
				})
				return
			}

			c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
			return
		}

		log.Debug().Bool("appAllowed", appAllowed).Msg("Checking if app is allowed")

		if !appAllowed {
			log.Warn().Str("username", userContext.Username).Str("host", host).Msg("User not allowed")

			c.Header("WWW-Authenticate", "Basic realm=\"tinyauth\"")

			if proxy.Proxy == "nginx" || !isBrowser {
				c.JSON(401, gin.H{
					"status":  401,
					"message": "Unauthorized",
				})
				return
			}

			queries, err := query.Values(types.UnauthorizedQuery{
				Username: userContext.Username,
				Resource: strings.Split(host, ".")[0],
			})

			if err != nil {
				log.Error().Err(err).Msg("Failed to build query")
				c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
				return
			}

			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
			return
		}

		c.Header("Remote-User", userContext.Username)

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	log.Debug().Msg("Unauthorized")

	c.Header("WWW-Authenticate", "Basic realm=\"tinyauth\"")

	if proxy.Proxy == "nginx" || !isBrowser {
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	queries, err := query.Values(types.LoginQuery{
		RedirectURI: fmt.Sprintf("%s://%s%s", proto, host, uri),
	})

	if err != nil {
		log.Error().Err(err).Msg("Failed to build query")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	log.Debug().Interface("redirect_uri", fmt.Sprintf("%s://%s%s", proto, host, uri)).Msg("Redirecting to login")

	c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/?%s", h.Config.AppURL, queries.Encode()))
}
