package controller

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"tinyauth/internal/config"
	"tinyauth/internal/service"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/rs/zerolog/log"
)

type OAuthRequest struct {
	Provider string `uri:"provider" binding:"required"`
}

type OAuthControllerConfig struct {
	CSRFCookieName     string
	RedirectCookieName string
	SecureCookie       bool
	AppURL             string
	Domain             string
}

type OAuthController struct {
	Config OAuthControllerConfig
	Router *gin.RouterGroup
	Auth   *service.AuthService
	Broker *service.OAuthBrokerService
}

func NewOAuthController(config OAuthControllerConfig, router *gin.RouterGroup, auth *service.AuthService, broker *service.OAuthBrokerService) *OAuthController {
	return &OAuthController{
		Config: config,
		Router: router,
		Auth:   auth,
		Broker: broker,
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
		log.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	service, exists := controller.Broker.GetService(req.Provider)

	if !exists {
		log.Warn().Msgf("OAuth provider not found: %s", req.Provider)
		c.JSON(404, gin.H{
			"status":  404,
			"message": "Not Found",
		})
		return
	}

	state := service.GenerateState()
	authURL := service.GetAuthURL(state)
	c.SetCookie(controller.Config.CSRFCookieName, state, int(time.Hour.Seconds()), "/", "", controller.Config.SecureCookie, true)

	redirectURI := c.Query("redirect_uri")

	if redirectURI != "" && utils.IsRedirectSafe(redirectURI, controller.Config.Domain) {
		log.Debug().Msg("Setting redirect URI cookie")
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
		log.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	state := c.Query("state")
	csrfCookie, err := c.Cookie(controller.Config.CSRFCookieName)

	if err != nil || state != csrfCookie {
		log.Warn().Err(err).Msg("CSRF token mismatch or cookie missing")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	c.SetCookie(controller.Config.CSRFCookieName, "", -1, "/", "", controller.Config.SecureCookie, true)

	code := c.Query("code")
	service, exists := controller.Broker.GetService(req.Provider)

	if !exists {
		log.Warn().Msgf("OAuth provider not found: %s", req.Provider)
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	err = service.VerifyCode(code)
	if err != nil {
		log.Error().Err(err).Msg("Failed to verify OAuth code")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	user, err := controller.Broker.GetUser(req.Provider)

	if err != nil {
		log.Error().Err(err).Msg("Failed to get user from OAuth provider")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	if user.Email == "" {
		log.Error().Msg("OAuth provider did not return an email")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	if !controller.Auth.EmailWhitelisted(user.Email) {
		queries, err := query.Values(config.UnauthorizedQuery{
			Username: user.Email,
		})

		if err != nil {
			log.Error().Err(err).Msg("Failed to encode unauthorized query")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", controller.Config.AppURL, queries.Encode()))
		return
	}

	var name string

	if user.Name != "" {
		log.Debug().Msg("Using name from OAuth provider")
		name = user.Name
	} else {
		log.Debug().Msg("No name from OAuth provider, using pseudo name")
		name = fmt.Sprintf("%s (%s)", utils.Capitalize(strings.Split(user.Email, "@")[0]), strings.Split(user.Email, "@")[1])
	}

	controller.Auth.CreateSessionCookie(c, &config.SessionCookie{
		Username:    user.Email,
		Name:        name,
		Email:       user.Email,
		Provider:    req.Provider,
		OAuthGroups: utils.CoalesceToString(user.Groups),
	})

	redirectURI, err := c.Cookie(controller.Config.RedirectCookieName)

	if err != nil || !utils.IsRedirectSafe(redirectURI, controller.Config.Domain) {
		log.Debug().Msg("No redirect URI cookie found, redirecting to app root")
		c.Redirect(http.StatusTemporaryRedirect, controller.Config.AppURL)
		return
	}

	queries, err := query.Values(config.RedirectQuery{
		RedirectURI: redirectURI,
	})

	if err != nil {
		log.Error().Err(err).Msg("Failed to encode redirect URI query")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.Config.AppURL))
		return
	}

	c.SetCookie(controller.Config.RedirectCookieName, "", -1, "/", "", controller.Config.SecureCookie, true)
	c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/continue?%s", controller.Config.AppURL, queries.Encode()))
}
