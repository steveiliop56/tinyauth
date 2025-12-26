package controller

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/service"
	"github.com/steveiliop56/tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/rs/zerolog/log"
)

var SupportedProxies = []string{"nginx", "traefik", "caddy", "envoy"}

type Proxy struct {
	Proxy string `uri:"proxy" binding:"required"`
}

type ProxyControllerConfig struct {
	AppURL string
}

type ProxyController struct {
	config ProxyControllerConfig
	router *gin.RouterGroup
	acls   *service.AccessControlsService
	auth   *service.AuthService
}

func NewProxyController(config ProxyControllerConfig, router *gin.RouterGroup, acls *service.AccessControlsService, auth *service.AuthService) *ProxyController {
	return &ProxyController{
		config: config,
		router: router,
		acls:   acls,
		auth:   auth,
	}
}

func (controller *ProxyController) SetupRoutes() {
	proxyGroup := controller.router.Group("/auth")
	proxyGroup.Any("/:proxy", controller.proxyHandler)
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

	if !slices.Contains(SupportedProxies, req.Proxy) {
		log.Warn().Str("proxy", req.Proxy).Msg("Invalid proxy")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	if req.Proxy != "envoy" && c.Request.Method != http.MethodGet {
		log.Warn().Str("method", c.Request.Method).Msg("Invalid method for proxy")
		c.JSON(405, gin.H{
			"status":  405,
			"message": "Method Not Allowed",
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

	// Get acls
	acls, err := controller.acls.GetAccessControls(host)

	if err != nil {
		log.Error().Err(err).Msg("Failed to get access controls for resource")
		controller.handleError(c, req, isBrowser)
		return
	}

	log.Trace().Interface("acls", acls).Msg("ACLs for resource")

	clientIP := c.ClientIP()

	if controller.auth.IsBypassedIP(acls.IP, clientIP) {
		controller.setHeaders(c, acls)
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	authEnabled, err := controller.auth.IsAuthEnabled(uri, acls.Path)

	if err != nil {
		log.Error().Err(err).Msg("Failed to check if auth is enabled for resource")
		controller.handleError(c, req, isBrowser)
		return
	}

	if !authEnabled {
		log.Debug().Msg("Authentication disabled for resource, allowing access")
		controller.setHeaders(c, acls)
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	if !controller.auth.CheckIP(acls.IP, clientIP) {
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
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", controller.config.AppURL, queries.Encode()))
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

	log.Trace().Interface("context", userContext).Msg("User context from request")

	if userContext.Provider == "basic" && userContext.TotpEnabled {
		log.Debug().Msg("User has TOTP enabled, denying basic auth access")
		userContext.IsLoggedIn = false
	}

	if userContext.IsLoggedIn {
		appAllowed := controller.auth.IsResourceAllowed(c, userContext, acls)

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

			if err != nil {
				log.Error().Err(err).Msg("Failed to encode unauthorized query")
				c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
				return
			}

			if userContext.OAuth {
				queries.Set("username", userContext.Email)
			} else {
				queries.Set("username", userContext.Username)
			}

			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", controller.config.AppURL, queries.Encode()))
			return
		}

		if userContext.OAuth {
			groupOK := controller.auth.IsInOAuthGroup(c, userContext, acls.OAuth.Groups)

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

				if err != nil {
					log.Error().Err(err).Msg("Failed to encode unauthorized query")
					c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
					return
				}

				if userContext.OAuth {
					queries.Set("username", userContext.Email)
				} else {
					queries.Set("username", userContext.Username)
				}

				c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", controller.config.AppURL, queries.Encode()))
				return
			}
		}

		c.Header("Remote-User", utils.SanitizeHeader(userContext.Username))
		c.Header("Remote-Name", utils.SanitizeHeader(userContext.Name))
		c.Header("Remote-Email", utils.SanitizeHeader(userContext.Email))
		c.Header("Remote-Groups", utils.SanitizeHeader(userContext.OAuthGroups))

		controller.setHeaders(c, acls)

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
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?%s", controller.config.AppURL, queries.Encode()))
}

func (controller *ProxyController) setHeaders(c *gin.Context, acls config.App) {
	c.Header("Authorization", c.Request.Header.Get("Authorization"))

	headers := utils.ParseHeaders(acls.Response.Headers)

	for key, value := range headers {
		log.Debug().Str("header", key).Msg("Setting header")
		c.Header(key, value)
	}

	basicPassword := utils.GetSecret(acls.Response.BasicAuth.Password, acls.Response.BasicAuth.PasswordFile)

	if acls.Response.BasicAuth.Username != "" && basicPassword != "" {
		log.Debug().Str("username", acls.Response.BasicAuth.Username).Msg("Setting basic auth header")
		c.Header("Authorization", fmt.Sprintf("Basic %s", utils.GetBasicAuth(acls.Response.BasicAuth.Username, basicPassword)))
	}
}

func (controller *ProxyController) handleError(c *gin.Context, req Proxy, isBrowser bool) {
	if req.Proxy == "nginx" || !isBrowser {
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
}
