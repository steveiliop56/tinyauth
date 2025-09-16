package bootstrap

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"tinyauth/internal/config"
	"tinyauth/internal/controller"
	"tinyauth/internal/middleware"
	"tinyauth/internal/service"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
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
	Config config.Config
}

func NewBootstrapApp(config config.Config) *BootstrapApp {
	return &BootstrapApp{
		Config: config,
	}
}

func (app *BootstrapApp) Setup() error {
	// Parse users
	users, err := utils.GetUsers(app.Config.Users, app.Config.UsersFile)

	if err != nil {
		return err
	}

	// Get OAuth configs
	oauthProviders, err := utils.GetOAuthProvidersConfig(os.Environ(), os.Args, app.Config.AppURL)

	if err != nil {
		return err
	}

	// Get cookie domain
	cookieDomain, err := utils.GetCookieDomain(app.Config.AppURL)

	if err != nil {
		return err
	}

	// Cookie names
	appUrl, _ := url.Parse(app.Config.AppURL) // Already validated
	cookieId := utils.GenerateIdentifier(appUrl.Hostname())
	sessionCookieName := fmt.Sprintf("%s-%s", config.SessionCookieName, cookieId)
	csrfCookieName := fmt.Sprintf("%s-%s", config.CSRFCookieName, cookieId)
	redirectCookieName := fmt.Sprintf("%s-%s", config.RedirectCookieName, cookieId)

	// Create configs
	authConfig := service.AuthServiceConfig{
		Users:             users,
		OauthWhitelist:    app.Config.OAuthWhitelist,
		SessionExpiry:     app.Config.SessionExpiry,
		SecureCookie:      app.Config.SecureCookie,
		CookieDomain:      cookieDomain,
		LoginTimeout:      app.Config.LoginTimeout,
		LoginMaxRetries:   app.Config.LoginMaxRetries,
		SessionCookieName: sessionCookieName,
	}

	// Setup services
	var ldapService *service.LdapService

	if app.Config.LdapAddress != "" {
		ldapConfig := service.LdapServiceConfig{
			Address:      app.Config.LdapAddress,
			BindDN:       app.Config.LdapBindDN,
			BindPassword: app.Config.LdapBindPassword,
			BaseDN:       app.Config.LdapBaseDN,
			Insecure:     app.Config.LdapInsecure,
			SearchFilter: app.Config.LdapSearchFilter,
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
		DatabasePath: app.Config.DatabasePath,
	})

	log.Debug().Str("service", fmt.Sprintf("%T", databaseService)).Msg("Initializing service")

	err = databaseService.Init()

	if err != nil {
		return fmt.Errorf("failed to initialize database service: %w", err)
	}

	database := databaseService.GetDatabase()

	// Create services
	dockerService := service.NewDockerService()
	authService := service.NewAuthService(authConfig, dockerService, ldapService, database)
	oauthBrokerService := service.NewOAuthBrokerService(oauthProviders)

	// Initialize services
	services := []Service{
		dockerService,
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
	babysit := map[string]string{
		"google": "Google",
		"github": "GitHub",
	}
	configuredProviders := make([]controller.Provider, 0)

	for id, provider := range oauthProviders {
		if id == "" {
			continue
		}

		if provider.Name == "" {
			if name, ok := babysit[id]; ok {
				provider.Name = name
			} else {
				provider.Name = utils.Capitalize(id)
			}
		}

		configuredProviders = append(configuredProviders, controller.Provider{
			Name:  provider.Name,
			ID:    id,
			OAuth: true,
		})
	}

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

	if len(app.Config.TrustedProxies) > 0 {
		engine.SetTrustedProxies(strings.Split(app.Config.TrustedProxies, ","))
	}

	if config.Version != "development" {
		gin.SetMode(gin.ReleaseMode)
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
		Title:                 app.Config.Title,
		AppURL:                app.Config.AppURL,
		CookieDomain:          cookieDomain,
		ForgotPasswordMessage: app.Config.ForgotPasswordMessage,
		BackgroundImage:       app.Config.BackgroundImage,
		OAuthAutoRedirect:     app.Config.OAuthAutoRedirect,
	}, apiRouter)

	oauthController := controller.NewOAuthController(controller.OAuthControllerConfig{
		AppURL:             app.Config.AppURL,
		SecureCookie:       app.Config.SecureCookie,
		CSRFCookieName:     csrfCookieName,
		RedirectCookieName: redirectCookieName,
		CookieDomain:       cookieDomain,
	}, apiRouter, authService, oauthBrokerService)

	proxyController := controller.NewProxyController(controller.ProxyControllerConfig{
		AppURL: app.Config.AppURL,
	}, apiRouter, dockerService, authService)

	userController := controller.NewUserController(controller.UserControllerConfig{
		CookieDomain: cookieDomain,
	}, apiRouter, authService)

	resourcesController := controller.NewResourcesController(controller.ResourcesControllerConfig{
		ResourcesDir: app.Config.ResourcesDir,
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

	// Start server
	address := fmt.Sprintf("%s:%d", app.Config.Address, app.Config.Port)
	log.Info().Msgf("Starting server on %s", address)
	if err := engine.Run(address); err != nil {
		log.Fatal().Err(err).Msg("Failed to start server")
	}

	return nil
}
