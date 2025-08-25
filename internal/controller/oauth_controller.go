package controller

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"tinyauth/internal/auth"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
)

type OAuthRequest struct {
	Provider string `uri:"provider" binding:"required"`
}

type OAuthControllerConfig struct {
	CSRFCookieName     string
	RedirectCookieName string
	SecureCookie       bool
	AppURL             string
}

type OAuthController struct {
	Config    OAuthControllerConfig
	Router    *gin.RouterGroup
	Auth      *auth.Auth
	Providers *providers.Providers
}

func NewOAuthController(config OAuthControllerConfig, router *gin.RouterGroup, auth *auth.Auth, providers *providers.Providers) *OAuthController {
	return &OAuthController{
		Config:    config,
		Router:    router,
		Auth:      auth,
		Providers: providers,
	}
}

func (controller *OAuthController) SetupRoutes() {
	oauthGroup := controller.Router.Group("/oauth")
	oauthGroup.GET("/url/:provider", controller.oauthURLHandler)
	oauthGroup.GET("/callback/:provider", controller.oauthCallbackHandler)
}

func (controller *OAuthController) oauthURLHandler(c *gin.Context) {
	var req OAuthRequest

	err := c.BindUri(&req)
	if err != nil {
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	provider := controller.Providers.GetProvider(req.Provider)

	if provider == nil {
		c.JSON(404, gin.H{
			"status":  404,
			"message": "Not Found",
		})
		return
	}

	state := provider.GenerateState()
	authURL := provider.GetAuthURL(state)
	c.SetCookie(controller.Config.CSRFCookieName, state, int(time.Hour.Seconds()), "/", "", controller.Config.SecureCookie, true)

	redirectURI := c.Query("redirect_uri")

	if redirectURI != "" {
		c.SetCookie(controller.Config.RedirectCookieName, redirectURI, int(time.Hour.Seconds()), "/", "", controller.Config.SecureCookie, true)
	}

	c.JSON(200, gin.H{
		"status":  200,
		"message": "OK",
		"url":     authURL,
	})
}

func (controller *OAuthController) oauthCallbackHandler(c *gin.Context) {
	var req OAuthRequest

	err := c.BindUri(&req)
	if err != nil {
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	state := c.Query("state")
	csrfCookie, err := c.Cookie(controller.Config.CSRFCookieName)

	if err != nil || state != csrfCookie {
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	c.SetCookie(controller.Config.CSRFCookieName, "", -1, "/", "", controller.Config.SecureCookie, true)

	code := c.Query("code")
	provider := controller.Providers.GetProvider(req.Provider)

	if provider == nil {
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	_, err = provider.ExchangeToken(code)
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	user, err := controller.Providers.GetUser(req.Provider)

	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	if user.Email == "" {
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	if !controller.Auth.EmailWhitelisted(user.Email) {
		queries, err := query.Values(types.UnauthorizedQuery{
			Username: user.Email,
		})

		if err != nil {
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", controller.Config.AppURL, queries.Encode()))
		return
	}

	var name string

	if user.Name != "" {
		name = user.Name
	} else {
		name = fmt.Sprintf("%s (%s)", utils.Capitalize(strings.Split(user.Email, "@")[0]), strings.Split(user.Email, "@")[1])
	}

	controller.Auth.CreateSessionCookie(c, &types.SessionCookie{
		Username:    user.Email,
		Name:        name,
		Email:       user.Email,
		Provider:    req.Provider,
		OAuthGroups: utils.CoalesceToString(user.Groups),
	})

	redirectURI, err := c.Cookie(controller.Config.RedirectCookieName)

	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, controller.Config.AppURL)
		return
	}

	queries, err := query.Values(types.RedirectQuery{
		RedirectURI: redirectURI,
	})

	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	c.SetCookie(controller.Config.RedirectCookieName, "", -1, "/", "", controller.Config.SecureCookie, true)
	c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?%s", controller.Config.AppURL, queries.Encode()))
}
