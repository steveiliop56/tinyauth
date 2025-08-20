package handlers

import (
	"tinyauth/internal/auth"
	"tinyauth/internal/docker"
	"tinyauth/internal/hooks"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"

	"github.com/gin-gonic/gin"
)

type Handlers struct {
	Config    types.HandlersConfig
	Auth      *auth.Auth
	Hooks     *hooks.Hooks
	Providers *providers.Providers
	Docker    *docker.Docker
}

func NewHandlers(config types.HandlersConfig, auth *auth.Auth, hooks *hooks.Hooks, providers *providers.Providers, docker *docker.Docker) *Handlers {
	return &Handlers{
		Config:    config,
		Auth:      auth,
		Hooks:     hooks,
		Providers: providers,
		Docker:    docker,
	}
}

func (h *Handlers) HealthcheckHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  200,
		"message": "OK",
	})
}
