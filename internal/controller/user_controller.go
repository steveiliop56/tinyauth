package controller

import (
	"fmt"
	"strings"
	"time"

	"github.com/steveiliop56/tinyauth/internal/repository"
	"github.com/steveiliop56/tinyauth/internal/service"
	"github.com/steveiliop56/tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TotpRequest struct {
	Code string `json:"code"`
}

type UserControllerConfig struct {
	CookieDomain string
}

type UserController struct {
	config UserControllerConfig
	router *gin.RouterGroup
	auth   *service.AuthService
}

func NewUserController(config UserControllerConfig, router *gin.RouterGroup, auth *service.AuthService) *UserController {
	return &UserController{
		config: config,
		router: router,
		auth:   auth,
	}
}

func (controller *UserController) SetupRoutes() {
	userGroup := controller.router.Group("/user")
	userGroup.POST("/login", controller.loginHandler)
	userGroup.POST("/logout", controller.logoutHandler)
	userGroup.POST("/totp", controller.totpHandler)
}

func (controller *UserController) loginHandler(c *gin.Context) {
	var req LoginRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind JSON")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	log.Debug().Str("username", req.Username).Msg("Login attempt")

	isLocked, remaining := controller.auth.IsAccountLocked(req.Username)

	if isLocked {
		log.Warn().Str("username", req.Username).Msg("Account is locked due to too many failed login attempts")
		c.Writer.Header().Add("x-tinyauth-lock-locked", "true")
		c.Writer.Header().Add("x-tinyauth-lock-reset", time.Now().Add(time.Duration(remaining)*time.Second).Format(time.RFC3339))
		c.JSON(429, gin.H{
			"status":  429,
			"message": fmt.Sprintf("Too many failed login attempts. Try again in %d seconds", remaining),
		})
		return
	}

	userSearch := controller.auth.SearchUser(req.Username)

	if userSearch.Type == "unknown" {
		log.Warn().Str("username", req.Username).Msg("User not found")
		controller.auth.RecordLoginAttempt(req.Username, false)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	if !controller.auth.VerifyUser(userSearch, req.Password) {
		log.Warn().Str("username", req.Username).Msg("Invalid password")
		controller.auth.RecordLoginAttempt(req.Username, false)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	log.Info().Str("username", req.Username).Msg("Login successful")

	controller.auth.RecordLoginAttempt(req.Username, true)

	if userSearch.Type == "local" {
		user := controller.auth.GetLocalUser(userSearch.Username)

		if user.TotpSecret != "" {
			log.Debug().Str("username", req.Username).Msg("User has TOTP enabled, requiring TOTP verification")

			err := controller.auth.CreateSessionCookie(c, &repository.Session{
				Username:    user.Username,
				Name:        utils.Capitalize(req.Username),
				Email:       fmt.Sprintf("%s@%s", strings.ToLower(req.Username), controller.config.CookieDomain),
				Provider:    "username",
				TotpPending: true,
			})

			if err != nil {
				log.Error().Err(err).Msg("Failed to create session cookie")
				c.JSON(500, gin.H{
					"status":  500,
					"message": "Internal Server Error",
				})
				return
			}

			c.JSON(200, gin.H{
				"status":      200,
				"message":     "TOTP required",
				"totpPending": true,
			})
			return
		}
	}

	sessionCookie := repository.Session{
		Username: req.Username,
		Name:     utils.Capitalize(req.Username),
		Email:    fmt.Sprintf("%s@%s", strings.ToLower(req.Username), controller.config.CookieDomain),
		Provider: "username",
	}

	log.Trace().Interface("session_cookie", sessionCookie).Msg("Creating session cookie")

	err = controller.auth.CreateSessionCookie(c, &sessionCookie)

	if err != nil {
		log.Error().Err(err).Msg("Failed to create session cookie")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Login successful",
	})
}

func (controller *UserController) logoutHandler(c *gin.Context) {
	log.Debug().Msg("Logout request received")

	controller.auth.DeleteSessionCookie(c)

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Logout successful",
	})
}

func (controller *UserController) totpHandler(c *gin.Context) {
	var req TotpRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind JSON")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	context, err := utils.GetContext(c)

	if err != nil {
		log.Error().Err(err).Msg("Failed to get user context")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	if !context.TotpPending {
		log.Warn().Msg("TOTP attempt without a pending TOTP session")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	log.Debug().Str("username", context.Username).Msg("TOTP verification attempt")

	isLocked, remaining := controller.auth.IsAccountLocked(context.Username)

	if isLocked {
		log.Warn().Str("username", context.Username).Msg("Account is locked due to too many failed TOTP attempts")
		c.Writer.Header().Add("x-tinyauth-lock-locked", "true")
		c.Writer.Header().Add("x-tinyauth-lock-reset", time.Now().Add(time.Duration(remaining)*time.Second).Format(time.RFC3339))
		c.JSON(429, gin.H{
			"status":  429,
			"message": fmt.Sprintf("Too many failed TOTP attempts. Try again in %d seconds", remaining),
		})
		return
	}

	user := controller.auth.GetLocalUser(context.Username)

	ok := totp.Validate(req.Code, user.TotpSecret)

	if !ok {
		log.Warn().Str("username", context.Username).Msg("Invalid TOTP code")
		controller.auth.RecordLoginAttempt(context.Username, false)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	log.Info().Str("username", context.Username).Msg("TOTP verification successful")

	controller.auth.RecordLoginAttempt(context.Username, true)

	sessionCookie := repository.Session{
		Username: user.Username,
		Name:     utils.Capitalize(user.Username),
		Email:    fmt.Sprintf("%s@%s", strings.ToLower(user.Username), controller.config.CookieDomain),
		Provider: "username",
	}

	log.Trace().Interface("session_cookie", sessionCookie).Msg("Creating session cookie")

	err = controller.auth.CreateSessionCookie(c, &sessionCookie)

	if err != nil {
		log.Error().Err(err).Msg("Failed to create session cookie")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Login successful",
	})
}
