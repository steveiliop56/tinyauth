package controller

import (
	"fmt"
	"net/url"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type UserContextResponse struct {
	Status      int    `json:"status"`
	Message     string `json:"message"`
	IsLoggedIn  bool   `json:"isLoggedIn"`
	Username    string `json:"username"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	Provider    string `json:"provider"`
	OAuth       bool   `json:"oauth"`
	TotpPending bool   `json:"totpPending"`
	OAuthName   string `json:"oauthName"`
}

type AppContextResponse struct {
	Status                int        `json:"status"`
	Message               string     `json:"message"`
	Providers             []Provider `json:"providers"`
	Title                 string     `json:"title"`
	AppURL                string     `json:"appUrl"`
	CookieDomain          string     `json:"cookieDomain"`
	ForgotPasswordMessage string     `json:"forgotPasswordMessage"`
	BackgroundImage       string     `json:"backgroundImage"`
	OAuthAutoRedirect     string     `json:"oauthAutoRedirect"`
}

type Provider struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	OAuth bool   `json:"oauth"`
}

type ContextControllerConfig struct {
	Providers             []Provider
	Title                 string
	AppURL                string
	CookieDomain          string
	ForgotPasswordMessage string
	BackgroundImage       string
	OAuthAutoRedirect     string
}

type ContextController struct {
	config ContextControllerConfig
	router *gin.RouterGroup
}

func NewContextController(config ContextControllerConfig, router *gin.RouterGroup) *ContextController {
	return &ContextController{
		config: config,
		router: router,
	}
}

func (controller *ContextController) SetupRoutes() {
	contextGroup := controller.router.Group("/context")
	contextGroup.GET("/user", controller.userContextHandler)
	contextGroup.GET("/app", controller.appContextHandler)
}

func (controller *ContextController) userContextHandler(c *gin.Context) {
	context, err := utils.GetContext(c)

	userContext := UserContextResponse{
		Status:      200,
		Message:     "Success",
		IsLoggedIn:  context.IsLoggedIn,
		Username:    context.Username,
		Name:        context.Name,
		Email:       context.Email,
		Provider:    context.Provider,
		OAuth:       context.OAuth,
		TotpPending: context.TotpPending,
		OAuthName:   context.OAuthName,
	}

	if err != nil {
		log.Debug().Err(err).Msg("No user context found in request")
		userContext.Status = 401
		userContext.Message = "Unauthorized"
		userContext.IsLoggedIn = false
		c.JSON(200, userContext)
		return
	}

	c.JSON(200, userContext)
}

func (controller *ContextController) appContextHandler(c *gin.Context) {
	appUrl, _ := url.Parse(controller.config.AppURL) // no need to check error, validated on startup

	c.JSON(200, AppContextResponse{
		Status:                200,
		Message:               "Success",
		Providers:             controller.config.Providers,
		Title:                 controller.config.Title,
		AppURL:                fmt.Sprintf("%s://%s", appUrl.Scheme, appUrl.Host),
		CookieDomain:          controller.config.CookieDomain,
		ForgotPasswordMessage: controller.config.ForgotPasswordMessage,
		BackgroundImage:       controller.config.BackgroundImage,
		OAuthAutoRedirect:     controller.config.OAuthAutoRedirect,
	})
}
