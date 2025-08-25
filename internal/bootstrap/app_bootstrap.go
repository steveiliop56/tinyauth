package bootstrap

import (
	"fmt"
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
	Name() string
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

	// Get domain
	domain, err := utils.GetUpperDomain(app.Config.AppURL)

	if err != nil {
		return err
	}

	// Cookie names
	cookieId := utils.GenerateIdentifier(strings.Split(domain, ".")[0])
	sessionCookieName := fmt.Sprintf("%s-%s", config.SessionCookieName, cookieId)
	csrfCookieName := fmt.Sprintf("%s-%s", config.CSRFCookieName, cookieId)
	redirectCookieName := fmt.Sprintf("%s-%s", config.RedirectCookieName, cookieId)

	// Secrets
	encryptionSecret, err := utils.DeriveKey(app.Config.Secret, "encryption")

	if err != nil {
		return err
	}

	hmacSecret, err := utils.DeriveKey(app.Config.Secret, "hmac")

	if err != nil {
		return err
	}

	// Create configs
	authConfig := service.AuthServiceConfig{
		Users:             users,
		OauthWhitelist:    app.Config.OAuthWhitelist,
		SessionExpiry:     app.Config.SessionExpiry,
		SecureCookie:      app.Config.SecureCookie,
		Domain:            domain,
		LoginTimeout:      app.Config.LoginTimeout,
		LoginMaxRetries:   app.Config.LoginMaxRetries,
		SessionCookieName: sessionCookieName,
		HMACSecret:        hmacSecret,
		EncryptionSecret:  encryptionSecret,
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
			ldapService = nil
		}
	}

	dockerService := service.NewDockerService()
	authService := service.NewAuthService(authConfig, dockerService, ldapService)
	oauthBrokerService := service.NewOAuthBrokerService(app.getOAuthBrokerConfig())

	// Initialize services
	services := []Service{
		dockerService,
		authService,
		oauthBrokerService,
	}

	for _, svc := range services {
		if svc != nil {
			err := svc.Init()
			if err != nil {
				return err
			}
		}
	}

	// Configured providers
	var configuredProviders []string

	if authService.UserAuthConfigured() || ldapService != nil {
		configuredProviders = append(configuredProviders, "username")
	}

	configuredProviders = append(configuredProviders, oauthBrokerService.GetConfiguredServices()...)

	if len(configuredProviders) == 0 {
		return fmt.Errorf("no authentication providers configured")
	}

	// Create engine
	engine := gin.New()
	router := engine.Group("/api")

	// Create middlewares
	var middlewares []Middleware

	contextMiddleware := middleware.NewContextMiddleware(middleware.ContextMiddlewareConfig{
		Domain: domain,
	}, authService, oauthBrokerService)

	uiMiddleware := middleware.NewUIMiddleware(middleware.UIMiddlewareConfig{
		ResourcesDir: app.Config.ResourcesDir,
	})
	zerologMiddleware := middleware.NewZerologMiddleware()

	middlewares = append(middlewares, contextMiddleware, uiMiddleware, zerologMiddleware)

	for _, middleware := range middlewares {
		log.Debug().Str("middleware", middleware.Name()).Msg("Initializing middleware")
		err := middleware.Init()
		if err != nil {
			return fmt.Errorf("failed to initialize %s middleware: %w", middleware.Name(), err)
		}
		router.Use(middleware.Middleware())
	}

	// Create controllers
	contextController := controller.NewContextController(controller.ContextControllerConfig{
		ConfiguredProviders:   configuredProviders,
		DisableContinue:       app.Config.DisableContinue,
		Title:                 app.Config.Title,
		GenericName:           app.Config.GenericName,
		Domain:                domain,
		ForgotPasswordMessage: app.Config.FogotPasswordMessage,
		BackgroundImage:       app.Config.BackgroundImage,
		OAuthAutoRedirect:     app.Config.OAuthAutoRedirect,
	}, router)

	oauthController := controller.NewOAuthController(controller.OAuthControllerConfig{
		AppURL:             app.Config.AppURL,
		SecureCookie:       app.Config.SecureCookie,
		CSRFCookieName:     csrfCookieName,
		RedirectCookieName: redirectCookieName,
	}, router, authService, oauthBrokerService)

	proxyController := controller.NewProxyController(controller.ProxyControllerConfig{
		AppURL: app.Config.AppURL,
	}, router, dockerService, authService)

	userController := controller.NewUserController(controller.UserControllerConfig{
		Domain: domain,
	}, router, authService)

	healthController := controller.NewHealthController(router)

	// Setup routes
	controller := []Controller{
		contextController,
		oauthController,
		proxyController,
		userController,
		healthController,
	}

	for _, ctrl := range controller {
		log.Debug().Msgf("Setting up %T routes", ctrl)
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

// Temporary
func (app *BootstrapApp) getOAuthBrokerConfig() map[string]config.OAuthServiceConfig {
	return map[string]config.OAuthServiceConfig{
		"google": {
			ClientID:     app.Config.GoogleClientId,
			ClientSecret: app.Config.GoogleClientSecret,
			RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/google", app.Config.AppURL),
		},
		"github": {
			ClientID:     app.Config.GithubClientId,
			ClientSecret: app.Config.GithubClientSecret,
			RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/github", app.Config.AppURL),
		},
		"generic": {
			ClientID:           app.Config.GenericClientId,
			ClientSecret:       app.Config.GenericClientSecret,
			RedirectURL:        fmt.Sprintf("%s/api/oauth/callback/generic", app.Config.AppURL),
			Scopes:             strings.Split(app.Config.GenericScopes, ","),
			AuthURL:            app.Config.GenericAuthURL,
			TokenURL:           app.Config.GenericTokenURL,
			UserinfoURL:        app.Config.GenericUserURL,
			InsecureSkipVerify: app.Config.GenericSkipSSL,
		},
	}

}
