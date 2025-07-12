package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/rs/zerolog/log"
)

func (h *Handlers) ProxyHandler(c *gin.Context) {
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

	// Check if the request is coming from a browser (tools like curl/bruno use */* and they don't include the text/html)
	isBrowser := strings.Contains(c.Request.Header.Get("Accept"), "text/html")

	if isBrowser {
		log.Debug().Msg("Request is most likely coming from a browser")
	} else {
		log.Debug().Msg("Request is most likely not coming from a browser")
	}

	log.Debug().Interface("proxy", proxy.Proxy).Msg("Got proxy")

	uri := c.Request.Header.Get("X-Forwarded-Uri")
	proto := c.Request.Header.Get("X-Forwarded-Proto")
	host := c.Request.Header.Get("X-Forwarded-Host")

	// Remove the port from the host if it exists
	hostPortless := strings.Split(host, ":")[0] // *lol*

	// Get the id
	id := strings.Split(hostPortless, ".")[0]

	labels, err := h.Docker.GetLabels(id, hostPortless)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get container labels")

		if proxy.Proxy == "nginx" || !isBrowser {
			c.JSON(500, gin.H{
				"status":  500,
				"message": "Internal Server Error",
			})
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	log.Debug().Interface("labels", labels).Msg("Got labels")

	ip := c.ClientIP()

	// Check if the IP is in bypass list
	if h.Auth.BypassedIP(labels, ip) {
		headersParsed := utils.ParseHeaders(labels.Headers)

		for key, value := range headersParsed {
			log.Debug().Str("key", key).Msg("Setting header")
			c.Header(key, value)
		}

		if labels.Basic.Username != "" && utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File) != "" {
			log.Debug().Str("username", labels.Basic.Username).Msg("Setting basic auth headers")
			c.Header("Authorization", fmt.Sprintf("Basic %s", utils.GetBasicAuth(labels.Basic.Username, utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File))))
		}

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	// Check if the IP is allowed/blocked
	if !h.Auth.CheckIP(labels, ip) {
		if proxy.Proxy == "nginx" || !isBrowser {
			c.JSON(403, gin.H{
				"status":  403,
				"message": "Forbidden",
			})
			return
		}

		values := types.UnauthorizedQuery{
			Resource: strings.Split(host, ".")[0],
			IP:       ip,
		}

		queries, err := query.Values(values)
		if err != nil {
			log.Error().Err(err).Msg("Failed to build queries")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
		return
	}

	// Check if auth is enabled
	authEnabled, err := h.Auth.AuthEnabled(uri, labels)
	if err != nil {
		log.Error().Err(err).Msg("Failed to check if app is allowed")
		if proxy.Proxy == "nginx" || !isBrowser {
			c.JSON(500, gin.H{
				"status":  500,
				"message": "Internal Server Error",
			})
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	// If auth is not enabled, return 200
	if !authEnabled {
		headersParsed := utils.ParseHeaders(labels.Headers)
		for key, value := range headersParsed {
			log.Debug().Str("key", key).Msg("Setting header")
			c.Header(key, value)
		}

		if labels.Basic.Username != "" && utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File) != "" {
			log.Debug().Str("username", labels.Basic.Username).Msg("Setting basic auth headers")
			c.Header("Authorization", fmt.Sprintf("Basic %s", utils.GetBasicAuth(labels.Basic.Username, utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File))))
		}

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})

		return
	}

	// Get user context
	userContext := h.Hooks.UseUserContext(c)

	// If we are using basic auth, we need to check if the user has totp and if it does then disable basic auth
	if userContext.Provider == "basic" && userContext.TotpEnabled {
		log.Warn().Str("username", userContext.Username).Msg("User has totp enabled, disabling basic auth")
		userContext.IsLoggedIn = false
	}

	// Check if user is logged in
	if userContext.IsLoggedIn {
		log.Debug().Msg("Authenticated")

		// Check if user is allowed to access subdomain, if request is nginx.example.com the subdomain (resource) is nginx
		appAllowed := h.Auth.ResourceAllowed(c, userContext, labels)

		log.Debug().Bool("appAllowed", appAllowed).Msg("Checking if app is allowed")

		if !appAllowed {
			log.Warn().Str("username", userContext.Username).Str("host", host).Msg("User not allowed")

			if proxy.Proxy == "nginx" || !isBrowser {
				c.JSON(401, gin.H{
					"status":  401,
					"message": "Unauthorized",
				})
				return
			}

			values := types.UnauthorizedQuery{
				Resource: strings.Split(host, ".")[0],
			}

			if userContext.OAuth {
				values.Username = userContext.Email
			} else {
				values.Username = userContext.Username
			}

			queries, err := query.Values(values)
			if err != nil {
				log.Error().Err(err).Msg("Failed to build queries")
				c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
				return
			}

			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
			return
		}

		// Check groups if using OAuth
		if userContext.OAuth {
			groupOk := h.Auth.OAuthGroup(c, userContext, labels)

			log.Debug().Bool("groupOk", groupOk).Msg("Checking if user is in required groups")

			if !groupOk {
				log.Warn().Str("username", userContext.Username).Str("host", host).Msg("User is not in required groups")
				if proxy.Proxy == "nginx" || !isBrowser {
					c.JSON(401, gin.H{
						"status":  401,
						"message": "Unauthorized",
					})
					return
				}

				values := types.UnauthorizedQuery{
					Resource: strings.Split(host, ".")[0],
					GroupErr: true,
				}

				if userContext.OAuth {
					values.Username = userContext.Email
				} else {
					values.Username = userContext.Username
				}

				queries, err := query.Values(values)
				if err != nil {
					log.Error().Err(err).Msg("Failed to build queries")
					c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
					return
				}

				c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
				return
			}
		}

		c.Header("Remote-User", utils.SanitizeHeader(userContext.Username))
		c.Header("Remote-Name", utils.SanitizeHeader(userContext.Name))
		c.Header("Remote-Email", utils.SanitizeHeader(userContext.Email))
		c.Header("Remote-Groups", utils.SanitizeHeader(userContext.OAuthGroups))

		// Set the rest of the headers
		parsedHeaders := utils.ParseHeaders(labels.Headers)
		for key, value := range parsedHeaders {
			log.Debug().Str("key", key).Msg("Setting header")
			c.Header(key, value)
		}

		// Set basic auth headers if configured
		if labels.Basic.Username != "" && utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File) != "" {
			log.Debug().Str("username", labels.Basic.Username).Msg("Setting basic auth headers")
			c.Header("Authorization", fmt.Sprintf("Basic %s", utils.GetBasicAuth(labels.Basic.Username, utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File))))
		}

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	// The user is not logged in
	log.Debug().Msg("Unauthorized")

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
		log.Error().Err(err).Msg("Failed to build queries")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	log.Debug().Interface("redirect_uri", fmt.Sprintf("%s://%s%s", proto, host, uri)).Msg("Redirecting to login")
	c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?%s", h.Config.AppURL, queries.Encode()))
}
