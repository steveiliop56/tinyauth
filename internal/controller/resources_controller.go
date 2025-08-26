package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type ResourcesControllerConfig struct {
	ResourcesDir string
}

type ResourcesController struct {
	Config     ResourcesControllerConfig
	Router     *gin.RouterGroup
	FileServer http.Handler
}

func NewResourcesController(config ResourcesControllerConfig, router *gin.RouterGroup) *ResourcesController {
	fileServer := http.StripPrefix("/resources", http.FileServer(http.Dir(config.ResourcesDir)))

	return &ResourcesController{
		Config:     config,
		Router:     router,
		FileServer: fileServer,
	}
}

func (controller *ResourcesController) SetupRoutes() {
	controller.Router.GET("/resources/*resource", controller.resourcesHandler)
}

func (controller *ResourcesController) resourcesHandler(c *gin.Context) {
	if controller.Config.ResourcesDir == "" {
		c.JSON(404, gin.H{
			"status":  404,
			"message": "Resources not found",
		})
		return
	}
	controller.FileServer.ServeHTTP(c.Writer, c.Request)
}
