package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
	"tinyauth/internal/config"
	"tinyauth/internal/controller"
	"tinyauth/internal/middleware"
	"tinyauth/internal/model"
	"tinyauth/internal/service"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

type Controller interface {
	SetupRoutes()
}

type Middleware interface {
	Middleware() gin.HandlerFunc
	Init() error
}

type Service interface {
	Init() error
}

type BootstrapApp struct {
	config config.Config
	uuid   string
}

func NewBootstrapApp(config config.Config) *BootstrapApp {
	return &BootstrapApp{
		config: config,
	}
}

func (app *BootstrapApp) Setup() error {
	// Parse users
	users, err := utils.GetUsers(app.config.Users, app.config.UsersFile)

	if err != nil {
		return err
	}

	// Get OAuth configs
	oauthProviders, err := utils.GetOAuthProvidersConfig(os.Environ(), os.Args, app.config.AppURL)

	if err != nil {
		return err
	}

	// Get cookie domain
	cookieDomain, err := utils.GetCookieDomain(app.config.AppURL)

	if err != nil {
		return err
	}

	// Cookie names
	appUrl, _ := url.Parse(app.config.AppURL) // Already validated
	uuid := utils.GenerateUUID(appUrl.Hostname())
	app.uuid = uuid
	cookieId := strings.Split(uuid, "-")[0]
	sessionCookieName := fmt.Sprintf("%s-%s", config.SessionCookieName, cookieId)
	csrfCookieName := fmt.Sprintf("%s-%s", config.CSRFCookieName, cookieId)
	redirectCookieName := fmt.Sprintf("%s-%s", config.RedirectCookieName, cookieId)

	// Dumps
	log.Trace().Interface("config", app.config).Msg("Config dump")
	log.Trace().Interface("users", users).Msg("Users dump")
	log.Trace().Interface("oauthProviders", oauthProviders).Msg("OAuth providers dump")
	log.Trace().Str("cookieDomain", cookieDomain).Msg("Cookie domain")
	log.Trace().Str("sessionCookieName", sessionCookieName).Msg("Session cookie name")
	log.Trace().Str("csrfCookieName", csrfCookieName).Msg("CSRF cookie name")
	log.Trace().Str("redirectCookieName", redirectCookieName).Msg("Redirect cookie name")

	// Create configs
	authConfig := service.AuthServiceConfig{
		Users:             users,
		OauthWhitelist:    app.config.OAuthWhitelist,
		SessionExpiry:     app.config.SessionExpiry,
		SecureCookie:      app.config.SecureCookie,
		CookieDomain:      cookieDomain,
		LoginTimeout:      app.config.LoginTimeout,
		LoginMaxRetries:   app.config.LoginMaxRetries,
		SessionCookieName: sessionCookieName,
	}

	// Setup services
	var ldapService *service.LdapService

	if app.config.LdapAddress != "" {
		ldapConfig := service.LdapServiceConfig{
			Address:      app.config.LdapAddress,
			BindDN:       app.config.LdapBindDN,
			BindPassword: app.config.LdapBindPassword,
			BaseDN:       app.config.LdapBaseDN,
			Insecure:     app.config.LdapInsecure,
			SearchFilter: app.config.LdapSearchFilter,
		}

		ldapService = service.NewLdapService(ldapConfig)

		err := ldapService.Init()

		if err != nil {
			log.Warn().Err(err).Msg("Failed to initialize LDAP service, continuing without LDAP")
			ldapService = nil
		}
	}

	// Bootstrap database
	databaseService := service.NewDatabaseService(service.DatabaseServiceConfig{
		DatabasePath: app.config.DatabasePath,
	})

	log.Debug().Str("service", fmt.Sprintf("%T", databaseService)).Msg("Initializing service")

	err = databaseService.Init()

	if err != nil {
		return fmt.Errorf("failed to initialize database service: %w", err)
	}

	database := databaseService.GetDatabase()

	// Create services
	dockerService := service.NewDockerService()
	aclsService := service.NewAccessControlsService(dockerService)
	authService := service.NewAuthService(authConfig, dockerService, ldapService, database)
	oauthBrokerService := service.NewOAuthBrokerService(oauthProviders)

	// Initialize services (order matters)
	services := []Service{
		dockerService,
		aclsService,
		authService,
		oauthBrokerService,
	}

	for _, svc := range services {
		if svc != nil {
			log.Debug().Str("service", fmt.Sprintf("%T", svc)).Msg("Initializing service")
			err := svc.Init()
			if err != nil {
				return err
			}
		}
	}

	// Configured providers
	configuredProviders := make([]controller.Provider, 0)

	for id, provider := range oauthProviders {
		configuredProviders = append(configuredProviders, controller.Provider{
			Name:  provider.Name,
			ID:    id,
			OAuth: true,
		})
	}

	sort.Slice(configuredProviders, func(i, j int) bool {
		return configuredProviders[i].Name < configuredProviders[j].Name
	})

	if authService.UserAuthConfigured() || ldapService != nil {
		configuredProviders = append(configuredProviders, controller.Provider{
			Name:  "Username",
			ID:    "username",
			OAuth: false,
		})
	}

	log.Debug().Interface("providers", configuredProviders).Msg("Authentication providers")

	if len(configuredProviders) == 0 {
		return fmt.Errorf("no authentication providers configured")
	}

	// Create engine
	engine := gin.New()
	engine.Use(gin.Recovery())

	if len(app.config.TrustedProxies) > 0 {
		err := engine.SetTrustedProxies(strings.Split(app.config.TrustedProxies, ","))

		if err != nil {
			return fmt.Errorf("failed to set trusted proxies: %w", err)
		}
	}

	// Create middlewares
	var middlewares []Middleware

	contextMiddleware := middleware.NewContextMiddleware(middleware.ContextMiddlewareConfig{
		CookieDomain: cookieDomain,
	}, authService, oauthBrokerService)

	uiMiddleware := middleware.NewUIMiddleware()
	zerologMiddleware := middleware.NewZerologMiddleware()

	middlewares = append(middlewares, contextMiddleware, uiMiddleware, zerologMiddleware)

	for _, middleware := range middlewares {
		log.Debug().Str("middleware", fmt.Sprintf("%T", middleware)).Msg("Initializing middleware")
		err := middleware.Init()
		if err != nil {
			return fmt.Errorf("failed to initialize middleware %T: %w", middleware, err)
		}
		engine.Use(middleware.Middleware())
	}

	// Create routers
	mainRouter := engine.Group("")
	apiRouter := engine.Group("/api")

	// Create controllers
	contextController := controller.NewContextController(controller.ContextControllerConfig{
		Providers:             configuredProviders,
		Title:                 app.config.Title,
		AppURL:                app.config.AppURL,
		CookieDomain:          cookieDomain,
		ForgotPasswordMessage: app.config.ForgotPasswordMessage,
		BackgroundImage:       app.config.BackgroundImage,
		OAuthAutoRedirect:     app.config.OAuthAutoRedirect,
	}, apiRouter)

	oauthController := controller.NewOAuthController(controller.OAuthControllerConfig{
		AppURL:             app.config.AppURL,
		SecureCookie:       app.config.SecureCookie,
		CSRFCookieName:     csrfCookieName,
		RedirectCookieName: redirectCookieName,
		CookieDomain:       cookieDomain,
	}, apiRouter, authService, oauthBrokerService)

	proxyController := controller.NewProxyController(controller.ProxyControllerConfig{
		AppURL: app.config.AppURL,
	}, apiRouter, aclsService, authService)

	userController := controller.NewUserController(controller.UserControllerConfig{
		CookieDomain: cookieDomain,
	}, apiRouter, authService)

	resourcesController := controller.NewResourcesController(controller.ResourcesControllerConfig{
		ResourcesDir:      app.config.ResourcesDir,
		ResourcesDisabled: app.config.DisableResources,
	}, mainRouter)

	healthController := controller.NewHealthController(apiRouter)

	// Setup routes
	controller := []Controller{
		contextController,
		oauthController,
		proxyController,
		userController,
		healthController,
		resourcesController,
	}

	for _, ctrl := range controller {
		log.Debug().Msgf("Setting up %T controller", ctrl)
		ctrl.SetupRoutes()
	}

	// If analytics are not disabled, start heartbeat
	if !app.config.DisableAnalytics {
		log.Debug().Msg("Starting heartbeat routine")
		go app.heartbeat()
	}

	// Start DB cleanup routine
	log.Debug().Msg("Starting database cleanup routine")
	go app.dbCleanup(database)

	// Start server
	address := fmt.Sprintf("%s:%d", app.config.Address, app.config.Port)
	log.Info().Msgf("Starting server on %s", address)
	if err := engine.Run(address); err != nil {
		log.Fatal().Err(err).Msg("Failed to start server")
	}

	return nil
}

func (app *BootstrapApp) heartbeat() {
	ticker := time.NewTicker(time.Duration(12) * time.Hour)
	defer ticker.Stop()

	type heartbeat struct {
		UUID    string `json:"uuid"`
		Version string `json:"version"`
	}

	var body heartbeat

	body.UUID = app.uuid
	body.Version = config.Version

	bodyJson, err := json.Marshal(body)

	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal heartbeat body")
		return
	}

	client := &http.Client{}

	heartbeatURL := config.ApiServer + "/v1/instances/heartbeat"

	for ; true; <-ticker.C {
		log.Debug().Msg("Sending heartbeat")

		req, err := http.NewRequest(http.MethodPost, heartbeatURL, bytes.NewReader(bodyJson))

		if err != nil {
			log.Error().Err(err).Msg("Failed to create heartbeat request")
			continue
		}

		req.Header.Add("Content-Type", "application/json")

		res, err := client.Do(req)

		if err != nil {
			log.Error().Err(err).Msg("Failed to send heartbeat")
			continue
		}

		res.Body.Close()

		if res.StatusCode != 200 && res.StatusCode != 201 {
			log.Debug().Str("status", res.Status).Msg("Heartbeat returned non-200/201 status")
		}
	}
}

func (app *BootstrapApp) dbCleanup(db *gorm.DB) {
	ticker := time.NewTicker(time.Duration(30) * time.Minute)
	defer ticker.Stop()
	ctx := context.Background()

	for ; true; <-ticker.C {
		log.Debug().Msg("Cleaning up old database sessions")
		_, err := gorm.G[model.Session](db).Where("expiry < ?", time.Now().UnixMilli()).Delete(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Failed to cleanup old sessions")
		}
	}
}
