package bootstrap

import (
	"tinyauth/internal/service"

	"github.com/rs/zerolog/log"
)

type Services struct {
	accessControlService *service.AccessControlsService
	authService          *service.AuthService
	databaseService      *service.DatabaseService
	dockerService        *service.DockerService
	ldapService          *service.LdapService
	oauthBrokerService   *service.OAuthBrokerService
}

func (app *BootstrapApp) initServices() (Services, error) {
	services := Services{}

	databaseService := service.NewDatabaseService(service.DatabaseServiceConfig{
		DatabasePath: app.config.DatabasePath,
	})

	err := databaseService.Init()

	if err != nil {
		return Services{}, err
	}

	services.databaseService = databaseService

	ldapService := service.NewLdapService(service.LdapServiceConfig{
		Address:      app.config.LdapAddress,
		BindDN:       app.config.LdapBindDN,
		BindPassword: app.config.LdapBindPassword,
		BaseDN:       app.config.LdapBaseDN,
		Insecure:     app.config.LdapInsecure,
		SearchFilter: app.config.LdapSearchFilter,
	})

	err = ldapService.Init()

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

	accessControlsService := service.NewAccessControlsService(dockerService)

	err = accessControlsService.Init()

	if err != nil {
		return Services{}, err
	}

	services.accessControlService = accessControlsService

	authService := service.NewAuthService(service.AuthServiceConfig{
		Users:             app.context.users,
		OauthWhitelist:    app.config.OAuthWhitelist,
		SessionExpiry:     app.config.SessionExpiry,
		SecureCookie:      app.config.SecureCookie,
		CookieDomain:      app.context.cookieDomain,
		LoginTimeout:      app.config.LoginTimeout,
		LoginMaxRetries:   app.config.LoginMaxRetries,
		SessionCookieName: app.context.sessionCookieName,
	}, dockerService, ldapService, databaseService.GetDatabase())

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
