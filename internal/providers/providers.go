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

func NewProviders(config types.OAuthConfig) *Providers {
	return &Providers{
		Config: config,
	}
}

type Providers struct {
	Config  types.OAuthConfig
	Github  *oauth.OAuth
	Google  *oauth.OAuth
	Generic *oauth.OAuth
}

func (providers *Providers) Init() {
	// If we have a client id and secret for github, initialize the oauth provider
	if providers.Config.GithubClientId != "" && providers.Config.GithubClientSecret != "" {
		log.Info().Msg("Initializing Github OAuth")

		// Create a new oauth provider with the github config
		providers.Github = oauth.NewOAuth(oauth2.Config{
			ClientID:     providers.Config.GithubClientId,
			ClientSecret: providers.Config.GithubClientSecret,
			RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/github", providers.Config.AppURL),
			Scopes:       GithubScopes(),
			Endpoint:     endpoints.GitHub,
		}, false)

		// Initialize the oauth provider
		providers.Github.Init()
	}

	// If we have a client id and secret for google, initialize the oauth provider
	if providers.Config.GoogleClientId != "" && providers.Config.GoogleClientSecret != "" {
		log.Info().Msg("Initializing Google OAuth")

		// Create a new oauth provider with the google config
		providers.Google = oauth.NewOAuth(oauth2.Config{
			ClientID:     providers.Config.GoogleClientId,
			ClientSecret: providers.Config.GoogleClientSecret,
			RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/google", providers.Config.AppURL),
			Scopes:       GoogleScopes(),
			Endpoint:     endpoints.Google,
		}, false)

		// Initialize the oauth provider
		providers.Google.Init()
	}

	// If we have a client id and secret for generic oauth, initialize the oauth provider
	if providers.Config.GenericClientId != "" && providers.Config.GenericClientSecret != "" {
		log.Info().Msg("Initializing Generic OAuth")

		// Create a new oauth provider with the generic config
		providers.Generic = oauth.NewOAuth(oauth2.Config{
			ClientID:     providers.Config.GenericClientId,
			ClientSecret: providers.Config.GenericClientSecret,
			RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/generic", providers.Config.AppURL),
			Scopes:       providers.Config.GenericScopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  providers.Config.GenericAuthURL,
				TokenURL: providers.Config.GenericTokenURL,
			},
		}, providers.Config.GenericSkipSSL)

		// Initialize the oauth provider
		providers.Generic.Init()
	}
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
