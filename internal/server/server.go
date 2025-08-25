package server

import (
	"fmt"
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

type Middleware interface {
	Middleware() gin.HandlerFunc
	Init() error
	Name() string
}

func NewServer(config types.ServerConfig, handlers *handlers.Handlers, middlewares []Middleware) (*Server, error) {
	router := gin.New()

	for _, middleware := range middlewares {
		log.Debug().Str("middleware", middleware.Name()).Msg("Initializing middleware")
		err := middleware.Init()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize middleware %s: %w", middleware.Name(), err)
		}
		router.Use(middleware.Middleware())
	}

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
