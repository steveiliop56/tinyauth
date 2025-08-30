package controller

import (
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
}

type AppContextResponse struct {
	Status                int      `json:"status"`
	Message               string   `json:"message"`
	ConfiguredProviders   []string `json:"configuredProviders"`
	Title                 string   `json:"title"`
	GenericName           string   `json:"genericName"`
	AppURL                string   `json:"appUrl"`
	RootDomain            string   `json:"rootDomain"`
	ForgotPasswordMessage string   `json:"forgotPasswordMessage"`
	BackgroundImage       string   `json:"backgroundImage"`
	OAuthAutoRedirect     string   `json:"oauthAutoRedirect"`
}

type ContextControllerConfig struct {
	ConfiguredProviders   []string
	DisableContinue       bool
	Title                 string
	GenericName           string
	AppURL                string
	RootDomain            string
	ForgotPasswordMessage string
	BackgroundImage       string
	OAuthAutoRedirect     string
}

type ContextController struct {
	Config ContextControllerConfig
	Router *gin.RouterGroup
}

func NewContextController(config ContextControllerConfig, router *gin.RouterGroup) *ContextController {
	return &ContextController{
		Config: config,
		Router: router,
	}
}

func (controller *ContextController) SetupRoutes() {
	contextGroup := controller.Router.Group("/context")
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
	c.JSON(200, AppContextResponse{
		Status:                200,
		Message:               "Success",
		ConfiguredProviders:   controller.Config.ConfiguredProviders,
		Title:                 controller.Config.Title,
		GenericName:           controller.Config.GenericName,
		AppURL:                controller.Config.AppURL,
		RootDomain:            controller.Config.RootDomain,
		ForgotPasswordMessage: controller.Config.ForgotPasswordMessage,
		BackgroundImage:       controller.Config.BackgroundImage,
		OAuthAutoRedirect:     controller.Config.OAuthAutoRedirect,
	})
}
