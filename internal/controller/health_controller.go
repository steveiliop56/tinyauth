package controller

import "github.com/gin-gonic/gin"

type HealthController struct {
	Router *gin.RouterGroup
}

func NewHealthController(router *gin.RouterGroup) *HealthController {
	return &HealthController{
		Router: router,
	}
}

func (controller *HealthController) SetupRoutes() {
	controller.Router.GET("/health", controller.healthHandler)
	controller.Router.HEAD("/health", controller.healthHandler)
}

func (controller *HealthController) healthHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  "ok",
		"message": "Healthy",
	})
}
