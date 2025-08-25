package controller

import (
	"fmt"
	"net/http"
	"strings"
	"tinyauth/internal/auth"
	"tinyauth/internal/docker"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
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
	Docker *docker.Docker
	Auth   *auth.Auth
}

func NewProxyController(config ProxyControllerConfig, router *gin.RouterGroup, docker *docker.Docker, auth *auth.Auth) *ProxyController {
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
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	isBrowser := strings.Contains(c.Request.Header.Get("Accept"), "text/html")

	uri := c.Request.Header.Get("X-Forwarded-Uri")
	proto := c.Request.Header.Get("X-Forwarded-Proto")
	host := c.Request.Header.Get("X-Forwarded-Host")

	hostWithoutPort := strings.Split(host, ":")[0]
	id := strings.Split(hostWithoutPort, ".")[0]

	labels, err := controller.Docker.GetLabels(id, hostWithoutPort)

	if err != nil {
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
			c.Header(key, value)
		}

		if labels.Basic.Username != "" && utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File) != "" {
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

		queries, err := query.Values(types.UnauthorizedQuery{
			Resource: strings.Split(host, ".")[0],
			IP:       clientIP,
		})

		if err != nil {
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", controller.Config.AppURL, queries.Encode()))
		return
	}

	authEnabled, err := controller.Auth.AuthEnabled(uri, labels)

	if err != nil {
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
		c.Header("Authorization", c.Request.Header.Get("Authorization"))

		headers := utils.ParseHeaders(labels.Headers)

		for key, value := range headers {
			c.Header(key, value)
		}

		if labels.Basic.Username != "" && utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File) != "" {
			c.Header("Authorization", fmt.Sprintf("Basic %s", utils.GetBasicAuth(labels.Basic.Username, utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File))))
		}

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	var userContext types.UserContext

	context, err := utils.GetContext(c)

	if err != nil {
		userContext = types.UserContext{
			IsLoggedIn: false,
		}
	} else {
		userContext = context
	}

	if userContext.Provider == "basic" && userContext.TotpEnabled {
		userContext.IsLoggedIn = false
	}

	if userContext.IsLoggedIn {
		appAllowed := controller.Auth.ResourceAllowed(c, userContext, labels)

		if !appAllowed {
			if req.Proxy == "nginx" || !isBrowser {
				c.JSON(403, gin.H{
					"status":  403,
					"message": "Forbidden",
				})
				return
			}

			queries, err := query.Values(types.UnauthorizedQuery{
				Resource: strings.Split(host, ".")[0],
			})

			if userContext.OAuth {
				queries.Set("username", userContext.Username)
			} else {
				queries.Set("username", userContext.Email)
			}

			if err != nil {
				c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
				return
			}

			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", controller.Config.AppURL, queries.Encode()))
			return
		}

		if userContext.OAuth {
			groupOK := controller.Auth.OAuthGroup(c, userContext, labels)

			if !groupOK {
				if req.Proxy == "nginx" || !isBrowser {
					c.JSON(403, gin.H{
						"status":  403,
						"message": "Forbidden",
					})
					return
				}

				queries, err := query.Values(types.UnauthorizedQuery{
					Resource: strings.Split(host, ".")[0],
					GroupErr: true,
				})

				if userContext.OAuth {
					queries.Set("username", userContext.Username)
				} else {
					queries.Set("username", userContext.Email)
				}

				if err != nil {
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
			c.Header(key, value)
		}

		if labels.Basic.Username != "" && utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File) != "" {
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

	queries, err := query.Values(types.RedirectQuery{
		RedirectURI: fmt.Sprintf("%s://%s%s", proto, host, uri),
	})

	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?%s", controller.Config.AppURL, queries.Encode()))
}
