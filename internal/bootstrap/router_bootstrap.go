package bootstrap

import (
	"fmt"

	"github.com/steveiliop56/tinyauth/internal/controller"
	"github.com/steveiliop56/tinyauth/internal/middleware"

	"github.com/gin-gonic/gin"
)

func (app *BootstrapApp) setupRouter() (*gin.Engine, error) {
	engine := gin.New()
	engine.Use(gin.Recovery())

	if len(app.config.Server.TrustedProxies) > 0 {
		err := engine.SetTrustedProxies(app.config.Server.TrustedProxies)

		if err != nil {
			return nil, fmt.Errorf("failed to set trusted proxies: %w", err)
		}
	}

	contextMiddleware := middleware.NewContextMiddleware(middleware.ContextMiddlewareConfig{
		CookieDomain: app.context.cookieDomain,
	}, app.services.authService, app.services.oauthBrokerService)

	err := contextMiddleware.Init()

	if err != nil {
		return nil, fmt.Errorf("failed to initialize context middleware: %w", err)
	}

	engine.Use(contextMiddleware.Middleware())

	uiMiddleware := middleware.NewUIMiddleware()

	err = uiMiddleware.Init()

	if err != nil {
		return nil, fmt.Errorf("failed to initialize UI middleware: %w", err)
	}

	engine.Use(uiMiddleware.Middleware())

	zerologMiddleware := middleware.NewZerologMiddleware()

	err = zerologMiddleware.Init()

	if err != nil {
		return nil, fmt.Errorf("failed to initialize zerolog middleware: %w", err)
	}

	engine.Use(zerologMiddleware.Middleware())

	apiRouter := engine.Group("/api")

	contextController := controller.NewContextController(controller.ContextControllerConfig{
		Providers:             app.context.configuredProviders,
		Title:                 app.config.UI.Title,
		AppURL:                app.config.AppURL,
		CookieDomain:          app.context.cookieDomain,
		ForgotPasswordMessage: app.config.UI.ForgotPasswordMessage,
		BackgroundImage:       app.config.UI.BackgroundImage,
		OAuthAutoRedirect:     app.config.OAuth.AutoRedirect,
		DisableUIWarnings:     app.config.DisableUIWarnings,
	}, apiRouter)

	contextController.SetupRoutes()

	oauthController := controller.NewOAuthController(controller.OAuthControllerConfig{
		AppURL:             app.config.AppURL,
		SecureCookie:       app.config.Auth.SecureCookie,
		CSRFCookieName:     app.context.csrfCookieName,
		RedirectCookieName: app.context.redirectCookieName,
		CookieDomain:       app.context.cookieDomain,
	}, apiRouter, app.services.authService, app.services.oauthBrokerService)

	oauthController.SetupRoutes()

	proxyController := controller.NewProxyController(controller.ProxyControllerConfig{
		AppURL: app.config.AppURL,
	}, apiRouter, app.services.accessControlService, app.services.authService)

	proxyController.SetupRoutes()

	userController := controller.NewUserController(controller.UserControllerConfig{
		CookieDomain: app.context.cookieDomain,
	}, apiRouter, app.services.authService)

	userController.SetupRoutes()

	resourcesController := controller.NewResourcesController(controller.ResourcesControllerConfig{
		ResourcesDir:      app.config.ResourcesDir,
		ResourcesDisabled: app.config.DisableResources,
	}, &engine.RouterGroup)

	resourcesController.SetupRoutes()

	healthController := controller.NewHealthController(apiRouter)

	healthController.SetupRoutes()

	return engine, nil
}
