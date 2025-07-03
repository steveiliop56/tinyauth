package providers

import (
	"fmt"
	"tinyauth/internal/constants"
	"tinyauth/internal/oauth"
	"tinyauth/internal/types"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

type Providers struct {
	Config  types.OAuthConfig
	Github  *oauth.OAuth
	Google  *oauth.OAuth
	Generic *oauth.OAuth
}

func NewProviders(config types.OAuthConfig) *Providers {
	providers := &Providers{
		Config: config,
	}

	// If we have a client id and secret for github, initialize the oauth provider
	if config.GithubClientId != "" && config.GithubClientSecret != "" {
		log.Info().Msg("Initializing Github OAuth")

		// Create a new oauth provider with the github config
		providers.Github = oauth.NewOAuth(oauth2.Config{
			ClientID:     config.GithubClientId,
			ClientSecret: config.GithubClientSecret,
			RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/github", config.AppURL),
			Scopes:       GithubScopes(),
			Endpoint:     endpoints.GitHub,
		}, false)
	}

	// If we have a client id and secret for google, initialize the oauth provider
	if config.GoogleClientId != "" && config.GoogleClientSecret != "" {
		log.Info().Msg("Initializing Google OAuth")

		// Create a new oauth provider with the google config
		providers.Google = oauth.NewOAuth(oauth2.Config{
			ClientID:     config.GoogleClientId,
			ClientSecret: config.GoogleClientSecret,
			RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/google", config.AppURL),
			Scopes:       GoogleScopes(),
			Endpoint:     endpoints.Google,
		}, false)
	}

	// If we have a client id and secret for generic oauth, initialize the oauth provider
	if config.GenericClientId != "" && config.GenericClientSecret != "" {
		log.Info().Msg("Initializing Generic OAuth")

		// Create a new oauth provider with the generic config
		providers.Generic = oauth.NewOAuth(oauth2.Config{
			ClientID:     config.GenericClientId,
			ClientSecret: config.GenericClientSecret,
			RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/generic", config.AppURL),
			Scopes:       config.GenericScopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.GenericAuthURL,
				TokenURL: config.GenericTokenURL,
			},
		}, config.GenericSkipSSL)
	}

	return providers
}

func (providers *Providers) GetProvider(provider string) *oauth.OAuth {
	// Return the provider based on the provider string
	switch provider {
	case "github":
		return providers.Github
	case "google":
		return providers.Google
	case "generic":
		return providers.Generic
	default:
		return nil
	}
}

func (providers *Providers) GetUser(provider string) (constants.Claims, error) {
	// Create user struct
	var user constants.Claims

	// Get the user from the provider
	switch provider {
	case "github":
		// If the github provider is not configured, return an error
		if providers.Github == nil {
			log.Debug().Msg("Github provider not configured")
			return user, nil
		}

		// Get the client from the github provider
		client := providers.Github.GetClient()

		log.Debug().Msg("Got client from github")

		// Get the user from the github provider
		user, err := GetGithubUser(client)

		// Check if there was an error
		if err != nil {
			return user, err
		}

		log.Debug().Msg("Got user from github")

		// Return the user
		return user, nil
	case "google":
		// If the google provider is not configured, return an error
		if providers.Google == nil {
			log.Debug().Msg("Google provider not configured")
			return user, nil
		}

		// Get the client from the google provider
		client := providers.Google.GetClient()

		log.Debug().Msg("Got client from google")

		// Get the user from the google provider
		user, err := GetGoogleUser(client)

		// Check if there was an error
		if err != nil {
			return user, err
		}

		log.Debug().Msg("Got user from google")

		// Return the user
		return user, nil
	case "generic":
		// If the generic provider is not configured, return an error
		if providers.Generic == nil {
			log.Debug().Msg("Generic provider not configured")
			return user, nil
		}

		// Get the client from the generic provider
		client := providers.Generic.GetClient()

		log.Debug().Msg("Got client from generic")

		// Get the user from the generic provider
		user, err := GetGenericUser(client, providers.Config.GenericUserURL)

		// Check if there was an error
		if err != nil {
			return user, err
		}

		log.Debug().Msg("Got user from generic")

		// Return the email
		return user, nil
	default:
		return user, nil
	}
}

func (provider *Providers) GetConfiguredProviders() []string {
	// Create a list of the configured providers
	providers := []string{}
	if provider.Github != nil {
		providers = append(providers, "github")
	}
	if provider.Google != nil {
		providers = append(providers, "google")
	}
	if provider.Generic != nil {
		providers = append(providers, "generic")
	}
	return providers
}
