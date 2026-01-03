package bootstrap

import (
	"github.com/steveiliop56/tinyauth/internal/repository"
	"github.com/steveiliop56/tinyauth/internal/service"

	"github.com/rs/zerolog/log"
)

type Services struct {
	accessControlService *service.AccessControlsService
	authService          *service.AuthService
	dockerService        *service.DockerService
	ldapService          *service.LdapService
	oauthBrokerService   *service.OAuthBrokerService
}

func (app *BootstrapApp) initServices(queries *repository.Queries) (Services, error) {
	services := Services{}

	ldapService := service.NewLdapService(service.LdapServiceConfig{
		Address:      app.config.Ldap.Address,
		BindDN:       app.config.Ldap.BindDN,
		BindPassword: app.config.Ldap.BindPassword,
		BaseDN:       app.config.Ldap.BaseDN,
		Insecure:     app.config.Ldap.Insecure,
		SearchFilter: app.config.Ldap.SearchFilter,
		AuthCert:     app.config.Ldap.AuthCert,
		AuthKey:      app.config.Ldap.AuthKey,
	})

	err := ldapService.Init()

	if err == nil {
		services.ldapService = ldapService
	} else {
		log.Warn().Err(err).Msg("Failed to initialize LDAP service, continuing without it")
	}

	dockerService := service.NewDockerService()

	err = dockerService.Init()

	if err != nil {
		return Services{}, err
	}

	services.dockerService = dockerService

	accessControlsService := service.NewAccessControlsService(dockerService, app.config.Apps)

	err = accessControlsService.Init()

	if err != nil {
		return Services{}, err
	}

	services.accessControlService = accessControlsService

	authService := service.NewAuthService(service.AuthServiceConfig{
		Users:              app.context.users,
		OauthWhitelist:     app.config.OAuth.Whitelist,
		SessionExpiry:      app.config.Auth.SessionExpiry,
		SessionMaxLifetime: app.config.Auth.SessionMaxLifetime,
		SecureCookie:       app.config.Auth.SecureCookie,
		CookieDomain:       app.context.cookieDomain,
		LoginTimeout:       app.config.Auth.LoginTimeout,
		LoginMaxRetries:    app.config.Auth.LoginMaxRetries,
		SessionCookieName:  app.context.sessionCookieName,
	}, dockerService, ldapService, queries)

	err = authService.Init()

	if err != nil {
		return Services{}, err
	}

	services.authService = authService

	oauthBrokerService := service.NewOAuthBrokerService(app.context.oauthProviders)

	err = oauthBrokerService.Init()

	if err != nil {
		return Services{}, err
	}

	services.oauthBrokerService = oauthBrokerService

	return services, nil
}
