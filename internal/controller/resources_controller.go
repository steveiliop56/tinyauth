package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type ResourcesControllerConfig struct {
	ResourcesDir string
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
	controller.fileServer.ServeHTTP(c.Writer, c.Request)
}
