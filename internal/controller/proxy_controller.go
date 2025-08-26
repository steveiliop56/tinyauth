package controller

import (
	"fmt"
	"net/http"
	"strings"
	"tinyauth/internal/config"
	"tinyauth/internal/service"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/rs/zerolog/log"
)

type Proxy struct {
	Proxy string `uri:"proxy" binding:"required"`
}

type ProxyControllerConfig struct {
	AppURL string
}

type ProxyController struct {
	Config ProxyControllerConfig
	Router *gin.RouterGroup
	Docker *service.DockerService
	Auth   *service.AuthService
}

func NewProxyController(config ProxyControllerConfig, router *gin.RouterGroup, docker *service.DockerService, auth *service.AuthService) *ProxyController {
	return &ProxyController{
		Config: config,
		Router: router,
		Docker: docker,
		Auth:   auth,
	}
}

func (controller *ProxyController) SetupRoutes() {
	proxyGroup := controller.Router.Group("/api/auth")
	proxyGroup.GET("/:proxy", controller.proxyHandler)
}

func (controller *ProxyController) proxyHandler(c *gin.Context) {
	var req Proxy

	err := c.BindUri(&req)
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
		log.Debug().Msg("Request identified as (most likely) coming from a browser")
	} else {
		log.Debug().Msg("Request identified as (most likely) coming from a non-browser client")
	}

	uri := c.Request.Header.Get("X-Forwarded-Uri")
	proto := c.Request.Header.Get("X-Forwarded-Proto")
	host := c.Request.Header.Get("X-Forwarded-Host")

	hostWithoutPort := strings.Split(host, ":")[0]
	id := strings.Split(hostWithoutPort, ".")[0]

	labels, err := controller.Docker.GetLabels(id, hostWithoutPort)

	if err != nil {
		log.Error().Err(err).Msg("Failed to get labels from Docker")

		if req.Proxy == "nginx" || !isBrowser {
			c.JSON(500, gin.H{
				"status":  500,
				"message": "Internal Server Error",
			})
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	clientIP := c.ClientIP()

	if controller.Auth.BypassedIP(labels, clientIP) {
		c.Header("Authorization", c.Request.Header.Get("Authorization"))

		headers := utils.ParseHeaders(labels.Headers)

		for key, value := range headers {
			log.Debug().Str("header", key).Msg("Setting header")
			c.Header(key, value)
		}

		if labels.Basic.Username != "" && utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File) != "" {
			log.Debug().Str("username", labels.Basic.Username).Msg("Setting basic auth header")
			c.Header("Authorization", fmt.Sprintf("Basic %s", utils.GetBasicAuth(labels.Basic.Username, utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File))))
		}

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	if !controller.Auth.CheckIP(labels, clientIP) {
		if req.Proxy == "nginx" || !isBrowser {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}

		queries, err := query.Values(config.UnauthorizedQuery{
			Resource: strings.Split(host, ".")[0],
			IP:       clientIP,
		})

		if err != nil {
			log.Error().Err(err).Msg("Failed to encode unauthorized query")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", controller.Config.AppURL, queries.Encode()))
		return
	}

	authEnabled, err := controller.Auth.AuthEnabled(uri, labels)

	if err != nil {
		log.Error().Err(err).Msg("Failed to check if auth is enabled for resource")

		if req.Proxy == "nginx" || !isBrowser {
			c.JSON(500, gin.H{
				"status":  500,
				"message": "Internal Server Error",
			})
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	if !authEnabled {
		log.Debug().Msg("Authentication disabled for resource, allowing access")

		c.Header("Authorization", c.Request.Header.Get("Authorization"))

		headers := utils.ParseHeaders(labels.Headers)

		for key, value := range headers {
			log.Debug().Str("header", key).Msg("Setting header")
			c.Header(key, value)
		}

		if labels.Basic.Username != "" && utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File) != "" {
			log.Debug().Str("username", labels.Basic.Username).Msg("Setting basic auth header")
			c.Header("Authorization", fmt.Sprintf("Basic %s", utils.GetBasicAuth(labels.Basic.Username, utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File))))
		}

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	var userContext config.UserContext

	context, err := utils.GetContext(c)

	if err != nil {
		log.Debug().Msg("No user context found in request, treating as not logged in")
		userContext = config.UserContext{
			IsLoggedIn: false,
		}
	} else {
		userContext = context
	}

	if userContext.Provider == "basic" && userContext.TotpEnabled {
		log.Debug().Msg("User has TOTP enabled, denying basic auth access")
		userContext.IsLoggedIn = false
	}

	if userContext.IsLoggedIn {
		appAllowed := controller.Auth.ResourceAllowed(c, userContext, labels)

		if !appAllowed {
			log.Warn().Str("user", userContext.Username).Str("resource", strings.Split(host, ".")[0]).Msg("User not allowed to access resource")

			if req.Proxy == "nginx" || !isBrowser {
				c.JSON(403, gin.H{
					"status":  403,
					"message": "Forbidden",
				})
				return
			}

			queries, err := query.Values(config.UnauthorizedQuery{
				Resource: strings.Split(host, ".")[0],
			})

			if userContext.OAuth {
				queries.Set("username", userContext.Username)
			} else {
				queries.Set("username", userContext.Email)
			}

			if err != nil {
				log.Error().Err(err).Msg("Failed to encode unauthorized query")
				c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
				return
			}

			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", controller.Config.AppURL, queries.Encode()))
			return
		}

		if userContext.OAuth {
			groupOK := controller.Auth.OAuthGroup(c, userContext, labels)

			if !groupOK {
				log.Warn().Str("user", userContext.Username).Str("resource", strings.Split(host, ".")[0]).Msg("User OAuth groups do not match resource requirements")

				if req.Proxy == "nginx" || !isBrowser {
					c.JSON(403, gin.H{
						"status":  403,
						"message": "Forbidden",
					})
					return
				}

				queries, err := query.Values(config.UnauthorizedQuery{
					Resource: strings.Split(host, ".")[0],
					GroupErr: true,
				})

				if userContext.OAuth {
					queries.Set("username", userContext.Username)
				} else {
					queries.Set("username", userContext.Email)
				}

				if err != nil {
					log.Error().Err(err).Msg("Failed to encode unauthorized query")
					c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
					return
				}

				c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", controller.Config.AppURL, queries.Encode()))
				return
			}
		}

		c.Header("Authorization", c.Request.Header.Get("Authorization"))
		c.Header("Remote-User", utils.SanitizeHeader(userContext.Username))
		c.Header("Remote-Name", utils.SanitizeHeader(userContext.Name))
		c.Header("Remote-Email", utils.SanitizeHeader(userContext.Email))
		c.Header("Remote-Groups", utils.SanitizeHeader(userContext.OAuthGroups))

		headers := utils.ParseHeaders(labels.Headers)

		for key, value := range headers {
			log.Debug().Str("header", key).Msg("Setting header")
			c.Header(key, value)
		}

		if labels.Basic.Username != "" && utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File) != "" {
			log.Debug().Str("username", labels.Basic.Username).Msg("Setting basic auth header")
			c.Header("Authorization", fmt.Sprintf("Basic %s", utils.GetBasicAuth(labels.Basic.Username, utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File))))
		}

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	if req.Proxy == "nginx" || !isBrowser {
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	queries, err := query.Values(config.RedirectQuery{
		RedirectURI: fmt.Sprintf("%s://%s%s", proto, host, uri),
	})

	if err != nil {
		log.Error().Err(err).Msg("Failed to encode redirect URI query")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?%s", controller.Config.AppURL, queries.Encode()))
}
