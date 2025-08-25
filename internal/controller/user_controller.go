package controller

import (
	"fmt"
	"strings"
	"tinyauth/internal/auth"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TotpRequest struct {
	Code string `json:"code"`
}

type UserControllerConfig struct {
	Domain string
}

type UserController struct {
	Config UserControllerConfig
	Router *gin.RouterGroup
	Auth   *auth.Auth
}

func NewUserController(config UserControllerConfig, router *gin.RouterGroup, auth *auth.Auth) *UserController {
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

	err := c.BindJSON(&req)
	if err != nil {
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

	isLocked, remainingTime := controller.Auth.IsAccountLocked(rateIdentifier)

	if isLocked {
		c.JSON(429, gin.H{
			"status":  429,
			"message": fmt.Sprintf("Too many failed login attempts. Try again in %d seconds", remainingTime),
		})
		return
	}

	userSearch := controller.Auth.SearchUser(req.Username)

	if userSearch.Type == "" {
		controller.Auth.RecordLoginAttempt(rateIdentifier, false)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	if !controller.Auth.VerifyUser(userSearch, req.Password) {
		controller.Auth.RecordLoginAttempt(rateIdentifier, false)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	controller.Auth.RecordLoginAttempt(rateIdentifier, true)

	if userSearch.Type == "local" {
		user := controller.Auth.GetLocalUser(userSearch.Username)

		if user.TotpSecret != "" {
			controller.Auth.CreateSessionCookie(c, &types.SessionCookie{
				Username:    user.Username,
				Name:        utils.Capitalize(req.Username),
				Email:       fmt.Sprintf("%s@%s", strings.ToLower(req.Username), controller.Config.Domain),
				Provider:    "username",
				TotpPending: true,
			})

			c.JSON(200, gin.H{
				"status":      200,
				"message":     "TOTP required",
				"totpPending": true,
			})
			return
		}
	}

	controller.Auth.CreateSessionCookie(c, &types.SessionCookie{
		Username: req.Username,
		Name:     utils.Capitalize(req.Username),
		Email:    fmt.Sprintf("%s@%s", strings.ToLower(req.Username), controller.Config.Domain),
		Provider: "username",
	})

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Login successful",
	})
}

func (controller *UserController) logoutHandler(c *gin.Context) {
	controller.Auth.DeleteSessionCookie(c)
	c.JSON(200, gin.H{
		"status":  200,
		"message": "Logout successful",
	})
}

func (controller *UserController) totpHandler(c *gin.Context) {
	var req TotpRequest

	err := c.BindJSON(&req)
	if err != nil {
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	context, err := utils.GetContext(c)

	if err != nil {
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	if !context.IsLoggedIn {
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

	isLocked, remainingTime := controller.Auth.IsAccountLocked(rateIdentifier)

	if isLocked {
		c.JSON(429, gin.H{
			"status":  429,
			"message": fmt.Sprintf("Too many failed login attempts. Try again in %d seconds", remainingTime),
		})
		return
	}

	user := controller.Auth.GetLocalUser(context.Username)

	ok := totp.Validate(req.Code, user.TotpSecret)

	if !ok {
		controller.Auth.RecordLoginAttempt(rateIdentifier, false)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	controller.Auth.RecordLoginAttempt(rateIdentifier, true)

	controller.Auth.CreateSessionCookie(c, &types.SessionCookie{
		Username: user.Username,
		Name:     utils.Capitalize(user.Username),
		Email:    fmt.Sprintf("%s@%s", strings.ToLower(user.Username), controller.Config.Domain),
		Provider: "username",
	})

	c.JSON(200, gin.H{
		"status":  200,
		"message": "Login successful",
	})
}
