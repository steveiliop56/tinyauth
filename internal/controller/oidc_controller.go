package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/utils/tlog"
)

type OIDCControllerConfig struct {
	Clients []config.OIDCClientConfig
}

type OIDCController struct {
	clients []config.OIDCClientConfig
	router  *gin.RouterGroup
}

func NewOIDCController(config OIDCControllerConfig, router *gin.RouterGroup) *OIDCController {
	return &OIDCController{
		clients: config.Clients,
		router:  router,
	}
}

func (controller *OIDCController) SetupRoutes() {
	oidcGroup := controller.router.Group("/oidc")
	oidcGroup.GET("/clients/:id", controller.GetClientInfo)
}

type ClientRequest struct {
	ClientID string `uri:"id" binding:"required"`
}

func (controller *OIDCController) GetClientInfo(c *gin.Context) {
	var req ClientRequest

	err := c.BindUri(&req)
	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	var client *config.OIDCClientConfig

	// Inefficient yeah, but it will be good until we have thousands of clients
	for _, clientCfg := range controller.clients {
		if clientCfg.ClientID == req.ClientID {
			client = &clientCfg
			break
		}
	}

	if client == nil {
		tlog.App.Warn().Str("client_id", req.ClientID).Msg("Client not found")
		c.JSON(404, gin.H{
			"status":  404,
			"message": "Client not found",
		})
		return
	}

	c.JSON(200, gin.H{
		"status": 200,
		"client": &client.ClientID,
		"name":   &client.Name,
	})
}
