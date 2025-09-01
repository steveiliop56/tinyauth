package controller

import "github.com/gin-gonic/gin"

type HealthController struct {
	router *gin.RouterGroup
}

func NewHealthController(router *gin.RouterGroup) *HealthController {
	return &HealthController{
		router: router,
	}
}

func (controller *HealthController) SetupRoutes() {
	controller.router.GET("/health", controller.healthHandler)
	controller.router.HEAD("/health", controller.healthHandler)
}

func (controller *HealthController) healthHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  "ok",
		"message": "Healthy",
	})
}
