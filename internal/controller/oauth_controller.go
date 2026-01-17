package controller

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/repository"
	"github.com/steveiliop56/tinyauth/internal/service"
	"github.com/steveiliop56/tinyauth/internal/utils"
	"github.com/steveiliop56/tinyauth/internal/utils/tlog"

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
	CookieDomain       string
}

type OAuthController struct {
	config OAuthControllerConfig
	router *gin.RouterGroup
	auth   *service.AuthService
	broker *service.OAuthBrokerService
}

func NewOAuthController(config OAuthControllerConfig, router *gin.RouterGroup, auth *service.AuthService, broker *service.OAuthBrokerService) *OAuthController {
	return &OAuthController{
		config: config,
		router: router,
		auth:   auth,
		broker: broker,
	}
}

func (controller *OAuthController) SetupRoutes() {
	oauthGroup := controller.router.Group("/oauth")
	oauthGroup.GET("/url/:provider", controller.oauthURLHandler)
	oauthGroup.GET("/callback/:provider", controller.oauthCallbackHandler)
}

func (controller *OAuthController) oauthURLHandler(c *gin.Context) {
	var req OAuthRequest

	err := c.BindUri(&req)
	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	service, exists := controller.broker.GetService(req.Provider)

	if !exists {
		tlog.App.Warn().Msgf("OAuth provider not found: %s", req.Provider)
		c.JSON(404, gin.H{
			"status":  404,
			"message": "Not Found",
		})
		return
	}

	service.GenerateVerifier()
	state := service.GenerateState()
	authURL := service.GetAuthURL(state)
	c.SetCookie(controller.config.CSRFCookieName, state, int(time.Hour.Seconds()), "/", fmt.Sprintf(".%s", controller.config.CookieDomain), controller.config.SecureCookie, true)

	redirectURI := c.Query("redirect_uri")
	isRedirectSafe := utils.IsRedirectSafe(redirectURI, controller.config.CookieDomain)

	if !isRedirectSafe {
		tlog.App.Warn().Str("redirect_uri", redirectURI).Msg("Unsafe redirect URI detected, ignoring")
		redirectURI = ""
	}

	if redirectURI != "" && isRedirectSafe {
		tlog.App.Debug().Msg("Setting redirect URI cookie")
		c.SetCookie(controller.config.RedirectCookieName, redirectURI, int(time.Hour.Seconds()), "/", fmt.Sprintf(".%s", controller.config.CookieDomain), controller.config.SecureCookie, true)
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
		tlog.App.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	state := c.Query("state")
	csrfCookie, err := c.Cookie(controller.config.CSRFCookieName)

	if err != nil || state != csrfCookie {
		tlog.App.Warn().Err(err).Msg("CSRF token mismatch or cookie missing")
		c.SetCookie(controller.config.CSRFCookieName, "", -1, "/", fmt.Sprintf(".%s", controller.config.CookieDomain), controller.config.SecureCookie, true)
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	c.SetCookie(controller.config.CSRFCookieName, "", -1, "/", fmt.Sprintf(".%s", controller.config.CookieDomain), controller.config.SecureCookie, true)

	code := c.Query("code")
	service, exists := controller.broker.GetService(req.Provider)

	if !exists {
		tlog.App.Warn().Msgf("OAuth provider not found: %s", req.Provider)
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	err = service.VerifyCode(code)
	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to verify OAuth code")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	user, err := controller.broker.GetUser(req.Provider)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to get user from OAuth provider")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	if user.Email == "" {
		tlog.App.Error().Msg("OAuth provider did not return an email")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	if !controller.auth.IsEmailWhitelisted(user.Email) {
		tlog.App.Warn().Str("email", user.Email).Msg("Email not whitelisted")
		tlog.AuditLoginFailure(c, user.Email, req.Provider, "email not whitelisted")

		queries, err := query.Values(config.UnauthorizedQuery{
			Username: user.Email,
		})

		if err != nil {
			tlog.App.Error().Err(err).Msg("Failed to encode unauthorized query")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", controller.config.AppURL, queries.Encode()))
		return
	}

	var name string

	if strings.TrimSpace(user.Name) != "" {
		tlog.App.Debug().Msg("Using name from OAuth provider")
		name = user.Name
	} else {
		tlog.App.Debug().Msg("No name from OAuth provider, using pseudo name")
		name = fmt.Sprintf("%s (%s)", utils.Capitalize(strings.Split(user.Email, "@")[0]), strings.Split(user.Email, "@")[1])
	}

	var username string

	if strings.TrimSpace(user.PreferredUsername) != "" {
		tlog.App.Debug().Msg("Using preferred username from OAuth provider")
		username = user.PreferredUsername
	} else {
		tlog.App.Debug().Msg("No preferred username from OAuth provider, using pseudo username")
		username = strings.Replace(user.Email, "@", "_", 1)
	}

	sessionCookie := repository.Session{
		Username:    username,
		Name:        name,
		Email:       user.Email,
		Provider:    req.Provider,
		OAuthGroups: utils.CoalesceToString(user.Groups),
		OAuthName:   service.GetName(),
		OAuthSub:    user.Sub,
	}

	tlog.App.Trace().Interface("session_cookie", sessionCookie).Msg("Creating session cookie")

	err = controller.auth.CreateSessionCookie(c, &sessionCookie)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to create session cookie")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	tlog.AuditLoginSuccess(c, sessionCookie.Username, sessionCookie.Provider)

	redirectURI, err := c.Cookie(controller.config.RedirectCookieName)

	if err != nil || !utils.IsRedirectSafe(redirectURI, controller.config.CookieDomain) {
		tlog.App.Debug().Msg("No redirect URI cookie found, redirecting to app root")
		c.Redirect(http.StatusTemporaryRedirect, controller.config.AppURL)
		return
	}

	queries, err := query.Values(config.RedirectQuery{
		RedirectURI: redirectURI,
	})

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to encode redirect URI query")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	c.SetCookie(controller.config.RedirectCookieName, "", -1, "/", fmt.Sprintf(".%s", controller.config.CookieDomain), controller.config.SecureCookie, true)
	c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/continue?%s", controller.config.AppURL, queries.Encode()))
}
