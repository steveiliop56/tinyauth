package handlers

import (
	"tinyauth/internal/auth"
	"tinyauth/internal/docker"
	"tinyauth/internal/providers"

	"github.com/gin-gonic/gin"
)

type HandlersConfig struct {
	AppURL                string
	Domain                string
	CookieSecure          bool
	DisableContinue       bool
	GenericName           string
	Title                 string
	ForgotPasswordMessage string
	BackgroundImage       string
	OAuthAutoRedirect     string
	CsrfCookieName        string
	RedirectCookieName    string
}

type Handlers struct {
	Config    HandlersConfig
	Auth      *auth.Auth
	Providers *providers.Providers
	Docker    *docker.Docker
}

func NewHandlers(config HandlersConfig, auth *auth.Auth, providers *providers.Providers, docker *docker.Docker) *Handlers {
	return &Handlers{
		Config:    config,
		Auth:      auth,
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
