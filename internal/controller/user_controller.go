package controller

import (
	"fmt"
	"strings"
	"tinyauth/internal/config"
	"tinyauth/internal/service"
	"tinyauth/internal/utils"

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
	RootDomain string
}

type UserController struct {
	Config UserControllerConfig
	Router *gin.RouterGroup
	Auth   *service.AuthService
}

func NewUserController(config UserControllerConfig, router *gin.RouterGroup, auth *service.AuthService) *UserController {
	return &UserController{
		Config: config,
		Router: router,
		Auth:   auth,
	}
}

func (controller *UserController) SetupRoutes() {
	userGroup := controller.Router.Group("/user")
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

	clientIP := c.ClientIP()

	rateIdentifier := req.Username

	if rateIdentifier == "" {
		rateIdentifier = clientIP
	}

	log.Debug().Str("username", req.Username).Str("ip", clientIP).Msg("Login attempt")

	isLocked, remainingTime := controller.Auth.IsAccountLocked(rateIdentifier)

	if isLocked {
		log.Warn().Str("username", req.Username).Str("ip", clientIP).Msg("Account is locked due to too many failed login attempts")
		c.JSON(429, gin.H{
			"status":  429,
			"message": fmt.Sprintf("Too many failed login attempts. Try again in %d seconds", remainingTime),
		})
		return
	}

	userSearch := controller.Auth.SearchUser(req.Username)

	if userSearch.Type == "" {
		log.Warn().Str("username", req.Username).Str("ip", clientIP).Msg("User not found")
		controller.Auth.RecordLoginAttempt(rateIdentifier, false)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	if !controller.Auth.VerifyUser(userSearch, req.Password) {
		log.Warn().Str("username", req.Username).Str("ip", clientIP).Msg("Invalid password")
		controller.Auth.RecordLoginAttempt(rateIdentifier, false)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	log.Info().Str("username", req.Username).Str("ip", clientIP).Msg("Login successful")

	controller.Auth.RecordLoginAttempt(rateIdentifier, true)

	if userSearch.Type == "local" {
		user := controller.Auth.GetLocalUser(userSearch.Username)

		if user.TotpSecret != "" {
			log.Debug().Str("username", req.Username).Msg("User has TOTP enabled, requiring TOTP verification")

			err := controller.Auth.CreateSessionCookie(c, &config.SessionCookie{
				Username:    user.Username,
				Name:        utils.Capitalize(req.Username),
				Email:       fmt.Sprintf("%s@%s", strings.ToLower(req.Username), controller.Config.RootDomain),
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

	err = controller.Auth.CreateSessionCookie(c, &config.SessionCookie{
		Username: req.Username,
		Name:     utils.Capitalize(req.Username),
		Email:    fmt.Sprintf("%s@%s", strings.ToLower(req.Username), controller.Config.RootDomain),
		Provider: "username",
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
		"status":  200,
		"message": "Login successful",
	})
}

func (controller *UserController) logoutHandler(c *gin.Context) {
	log.Debug().Msg("Logout request received")

	controller.Auth.DeleteSessionCookie(c)

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

	clientIP := c.ClientIP()

	rateIdentifier := context.Username

	if rateIdentifier == "" {
		rateIdentifier = clientIP
	}

	log.Debug().Str("username", context.Username).Str("ip", clientIP).Msg("TOTP verification attempt")

	isLocked, remainingTime := controller.Auth.IsAccountLocked(rateIdentifier)

	if isLocked {
		log.Warn().Str("username", context.Username).Str("ip", clientIP).Msg("Account is locked due to too many failed TOTP attempts")
		c.JSON(429, gin.H{
			"status":  429,
			"message": fmt.Sprintf("Too many failed login attempts. Try again in %d seconds", remainingTime),
		})
		return
	}

	user := controller.Auth.GetLocalUser(context.Username)

	ok := totp.Validate(req.Code, user.TotpSecret)

	if !ok {
		log.Warn().Str("username", context.Username).Str("ip", clientIP).Msg("Invalid TOTP code")
		controller.Auth.RecordLoginAttempt(rateIdentifier, false)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	log.Info().Str("username", context.Username).Str("ip", clientIP).Msg("TOTP verification successful")

	controller.Auth.RecordLoginAttempt(rateIdentifier, true)

	err = controller.Auth.CreateSessionCookie(c, &config.SessionCookie{
		Username: user.Username,
		Name:     utils.Capitalize(user.Username),
		Email:    fmt.Sprintf("%s@%s", strings.ToLower(user.Username), controller.Config.RootDomain),
		Provider: "username",
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
		"status":  200,
		"message": "Login successful",
	})
}
