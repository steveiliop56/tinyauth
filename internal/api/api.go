package api

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"
	"tinyauth/internal/assets"
	"tinyauth/internal/handlers"
	"tinyauth/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func NewAPI(config types.APIConfig, handlers *handlers.Handlers) *API {
	return &API{
		Config:   config,
		Handlers: handlers,
	}
}

type API struct {
	Config   types.APIConfig
	Router   *gin.Engine
	Handlers *handlers.Handlers
}

func (api *API) Init() {
	// Disable gin logs
	gin.SetMode(gin.ReleaseMode)

	// Create router and use zerolog for logs
	log.Debug().Msg("Setting up router")
	router := gin.New()
	router.Use(zerolog())

	// Read UI assets
	log.Debug().Msg("Setting up assets")
	dist, err := fs.Sub(assets.Assets, "dist")

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get UI assets")
	}

	// Create file server
	log.Debug().Msg("Setting up file server")
	fileServer := http.FileServer(http.FS(dist))

	// UI middleware
	router.Use(func(c *gin.Context) {
		// If not an API request, serve the UI
		if !strings.HasPrefix(c.Request.URL.Path, "/api") {
			// Check if the file exists
			_, err := fs.Stat(dist, strings.TrimPrefix(c.Request.URL.Path, "/"))

			// If the file doesn't exist, serve the index.html
			if os.IsNotExist(err) {
				c.Request.URL.Path = "/"
			}

			// Serve the file
			fileServer.ServeHTTP(c.Writer, c.Request)

			// Stop further processing
			c.Abort()
		}
	})

	// Set router
	api.Router = router
}

func (api *API) SetupRoutes() {
	// Proxy
	api.Router.GET("/api/auth/:proxy", api.Handlers.AuthHandler)

	// Auth
	api.Router.POST("/api/login", api.Handlers.LoginHandler)
	api.Router.POST("/api/totp", api.Handlers.TotpHandler)
	api.Router.POST("/api/logout", api.Handlers.LogoutHandler)

	// Context
	api.Router.GET("/api/app", api.Handlers.AppHandler)
	api.Router.GET("/api/user", api.Handlers.UserHandler)

	// OAuth
	api.Router.GET("/api/oauth/url/:provider", api.Handlers.OauthUrlHandler)
	api.Router.GET("/api/oauth/callback/:provider", api.Handlers.OauthCallbackHandler)

	// App
	api.Router.GET("/api/healthcheck", api.Handlers.HealthcheckHandler)
}

func (api *API) Run() {
	log.Info().Str("address", api.Config.Address).Int("port", api.Config.Port).Msg("Starting server")

	// Run server
	err := api.Router.Run(fmt.Sprintf("%s:%d", api.Config.Address, api.Config.Port))

	// Check for errors
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to start server")
	}
}

// zerolog is a middleware for gin that logs requests using zerolog
func zerolog() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get initial time
		tStart := time.Now()

		// Process request
		c.Next()

		// Get status code, address, method and path
		code := c.Writer.Status()
		address := c.Request.RemoteAddr
		method := c.Request.Method
		path := c.Request.URL.Path

		// Get latency
		latency := time.Since(tStart).String()

		// Log request
		switch {
		case code >= 200 && code < 300:
			log.Info().Str("method", method).Str("path", path).Str("address", address).Int("status", code).Str("latency", latency).Msg("Request")
		case code >= 300 && code < 400:
			log.Warn().Str("method", method).Str("path", path).Str("address", address).Int("status", code).Str("latency", latency).Msg("Request")
		case code >= 400:
			log.Error().Str("method", method).Str("path", path).Str("address", address).Int("status", code).Str("latency", latency).Msg("Request")
		}
	}
}
