package providers

import (
	"fmt"
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
	if providers.Config.GithubClientId != "" && providers.Config.GithubClientSecret != "" {
		log.Info().Msg("Initializing Github OAuth")
		providers.Github = oauth.NewOAuth(oauth2.Config{
			ClientID:     providers.Config.GithubClientId,
			ClientSecret: providers.Config.GithubClientSecret,
			RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/github", providers.Config.AppURL),
			Scopes:       GithubScopes(),
			Endpoint:     endpoints.GitHub,
		})
		providers.Github.Init()
	}
	if providers.Config.GoogleClientId != "" && providers.Config.GoogleClientSecret != "" {
		log.Info().Msg("Initializing Google OAuth")
		providers.Google = oauth.NewOAuth(oauth2.Config{
			ClientID:     providers.Config.GoogleClientId,
			ClientSecret: providers.Config.GoogleClientSecret,
			RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/google", providers.Config.AppURL),
			Scopes:       GoogleScopes(),
			Endpoint:     endpoints.Google,
		})
		providers.Google.Init()
	}
	if providers.Config.GenericClientId != "" && providers.Config.GenericClientSecret != "" {
		log.Info().Msg("Initializing Generic OAuth")
		providers.Generic = oauth.NewOAuth(oauth2.Config{
			ClientID:     providers.Config.GenericClientId,
			ClientSecret: providers.Config.GenericClientSecret,
			RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/generic", providers.Config.AppURL),
			Scopes:       providers.Config.GenericScopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  providers.Config.GenericAuthURL,
				TokenURL: providers.Config.GenericTokenURL,
			},
		})
		providers.Generic.Init()
	}
}

func (providers *Providers) GetProvider(provider string) *oauth.OAuth {
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

func (providers *Providers) GetUser(provider string) (string, error) {
	switch provider {
	case "github":
		if providers.Github == nil {
			return "", nil
		}
		client := providers.Github.GetClient()
		email, emailErr := GetGithubEmail(client)
		if emailErr != nil {
			return "", emailErr
		}
		return email, nil
	case "google":
		if providers.Google == nil {
			return "", nil
		}
		client := providers.Google.GetClient()
		email, emailErr := GetGoogleEmail(client)
		if emailErr != nil {
			return "", emailErr
		}
		return email, nil
	case "generic":
		if providers.Generic == nil {
			return "", nil
		}
		client := providers.Generic.GetClient()
		email, emailErr := GetGenericEmail(client, providers.Config.GenericUserURL)
		if emailErr != nil {
			return "", emailErr
		}
		return email, nil
	default:
		return "", nil
	}
}

func (provider *Providers) GetConfiguredProviders() []string {
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
