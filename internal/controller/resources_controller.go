package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type ResourcesControllerConfig struct {
	ResourcesDir string
}

type ResourcesController struct {
	Config ResourcesControllerConfig
	Router *gin.RouterGroup
}

func NewResourcesController(config ResourcesControllerConfig, router *gin.RouterGroup) *ResourcesController {
	return &ResourcesController{
		Config: config,
		Router: router,
	}
}

func (controller *ResourcesController) SetupRoutes() {
	controller.Router.GET("/resources/*resource", controller.resourcesHandler)
}

func (controller *ResourcesController) resourcesHandler(c *gin.Context) {
	fileServer := http.StripPrefix("/resources", http.FileServer(http.Dir(controller.Config.ResourcesDir)))
	fileServer.ServeHTTP(c.Writer, c.Request)
}
