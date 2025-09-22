package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type ResourcesControllerConfig struct {
	ResourcesDir      string
	ResourcesDisabled bool
}

type ResourcesController struct {
	config     ResourcesControllerConfig
	router     *gin.RouterGroup
	fileServer http.Handler
}

func NewResourcesController(config ResourcesControllerConfig, router *gin.RouterGroup) *ResourcesController {
	fileServer := http.StripPrefix("/resources", http.FileServer(http.Dir(config.ResourcesDir)))

	return &ResourcesController{
		config:     config,
		router:     router,
		fileServer: fileServer,
	}
}

func (controller *ResourcesController) SetupRoutes() {
	controller.router.GET("/resources/*resource", controller.resourcesHandler)
}

func (controller *ResourcesController) resourcesHandler(c *gin.Context) {
	if controller.config.ResourcesDir == "" {
		c.JSON(404, gin.H{
			"status":  404,
			"message": "Resources not found",
		})
		return
	}
	if controller.config.ResourcesDisabled {
		c.JSON(403, gin.H{
			"status":  403,
			"message": "Resources are disabled",
		})
		return
	}
	controller.fileServer.ServeHTTP(c.Writer, c.Request)
}
