package server

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

type Server struct {
	Config   types.ServerConfig
	Handlers *handlers.Handlers
	Router   *gin.Engine
}

var (
	loggerSkipPathsPrefix = []string{
		"GET /api/healthcheck", 
		"HEAD /api/healthcheck", 
		"GET /favicon.ico",
	}
)

func logPath(path string) bool{
	for _, prefix := range loggerSkipPathsPrefix {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}
	return true
}

func NewServer(config types.ServerConfig, handlers *handlers.Handlers) (*Server, error) {
	gin.SetMode(gin.ReleaseMode)

	log.Debug().Msg("Setting up router")
	router := gin.New()
	router.Use(zerolog())

	log.Debug().Msg("Setting up assets")
	dist, err := fs.Sub(assets.Assets, "dist")
	if err != nil {
		return nil, err
	}

	log.Debug().Msg("Setting up file server")
	fileServer := http.FileServer(http.FS(dist))

	// UI middleware
	router.Use(func(c *gin.Context) {
		// If not an API request, serve the UI
		if !strings.HasPrefix(c.Request.URL.Path, "/api") {
			_, err := fs.Stat(dist, strings.TrimPrefix(c.Request.URL.Path, "/"))
			if os.IsNotExist(err) {
				c.Request.URL.Path = "/"
			}
			fileServer.ServeHTTP(c.Writer, c.Request)
			c.Abort()
		}
	})

	// Proxy routes
	router.GET("/api/auth/:proxy", handlers.ProxyHandler)

	// Auth routes
	router.POST("/api/login", handlers.LoginHandler)
	router.POST("/api/totp", handlers.TOTPHandler)
	router.POST("/api/logout", handlers.LogoutHandler)

	// Context routes
	router.GET("/api/app", handlers.AppContextHandler)
	router.GET("/api/user", handlers.UserContextHandler)

	// OAuth routes
	router.GET("/api/oauth/url/:provider", handlers.OAuthURLHandler)
	router.GET("/api/oauth/callback/:provider", handlers.OAuthCallbackHandler)

	// App routes
	router.GET("/api/healthcheck", handlers.HealthcheckHandler)
	router.HEAD("/api/healthcheck", handlers.HealthcheckHandler)

	return &Server{
		Config:   config,
		Handlers: handlers,
		Router:   router,
	}, nil
}

func (s *Server) Start() error {
	log.Info().Str("address", s.Config.Address).Int("port", s.Config.Port).Msg("Starting server")
	return s.Router.Run(fmt.Sprintf("%s:%d", s.Config.Address, s.Config.Port))
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
		if logPath(method + " " + path) {
			switch {
				case code >= 200 && code < 300:
					log.Info().Str("method", method).Str("path", path).Str("address", address).Int("status", code).Str("latency", latency).Msg("Request")
				case code >= 300 && code < 400:
					log.Warn().Str("method", method).Str("path", path).Str("address", address).Int("status", code).Str("latency", latency).Msg("Request")
				case code >= 400:
					log.Error().Str("method", method).Str("path", path).Str("address", address).Int("status", code).Str("latency", latency).Msg("Request")
			}
		}else{
			log.Debug().Str("method", method).Str("path", path).Str("address", address).Int("status", code).Str("latency", latency).Msg("Request")
		}		
	}
}