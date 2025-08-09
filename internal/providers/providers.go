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
   Config     types.OAuthConfig
   Github     *oauth.OAuth
   Google     *oauth.OAuth
   Microsoft  *oauth.OAuth
   Generic    *oauth.OAuth
}

func NewProviders(config types.OAuthConfig) *Providers {
	providers := &Providers{
		Config: config,
	}

   if config.GithubClientId != "" && config.GithubClientSecret != "" {
	   log.Info().Msg("Initializing Github OAuth")
	   providers.Github = oauth.NewOAuth(oauth2.Config{
		   ClientID:     config.GithubClientId,
		   ClientSecret: config.GithubClientSecret,
		   RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/github", config.AppURL),
		   Scopes:       GithubScopes(),
		   Endpoint:     endpoints.GitHub,
	   }, false)
   }

   if config.GoogleClientId != "" && config.GoogleClientSecret != "" {
	   log.Info().Msg("Initializing Google OAuth")
	   providers.Google = oauth.NewOAuth(oauth2.Config{
		   ClientID:     config.GoogleClientId,
		   ClientSecret: config.GoogleClientSecret,
		   RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/google", config.AppURL),
		   Scopes:       GoogleScopes(),
		   Endpoint:     endpoints.Google,
	   }, false)
   }

   if config.MicrosoftClientId != "" && config.MicrosoftClientSecret != "" {
	   log.Info().Msg("Initializing Microsoft OAuth")

	   // Use custom endpoints if provided, otherwise fall back to defaults
	   authURL := config.MicrosoftAuthURL
	   if authURL == "" {
		   authURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	   }

	   tokenURL := config.MicrosoftTokenURL
	   if tokenURL == "" {
		   tokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	   }

	   // Use custom scopes if provided, otherwise fall back to defaults
	   scopes := config.MicrosoftScopes
	   if len(scopes) == 0 || (len(scopes) == 1 && scopes[0] == "") {
		   scopes = MicrosoftScopes()
	   }

	   providers.Microsoft = oauth.NewOAuth(oauth2.Config{
		   ClientID:     config.MicrosoftClientId,
		   ClientSecret: config.MicrosoftClientSecret,
		   RedirectURL:  fmt.Sprintf("%s/api/oauth/callback/microsoft", config.AppURL),
		   Scopes:       scopes,
		   Endpoint: oauth2.Endpoint{
			   AuthURL:  authURL,
			   TokenURL: tokenURL,
		   },
	   }, false)
   }

	if config.GenericClientId != "" && config.GenericClientSecret != "" {
		log.Info().Msg("Initializing Generic OAuth")
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
   switch provider {
   case "github":
	   return providers.Github
   case "google":
	   return providers.Google
   case "microsoft":
	   return providers.Microsoft
   case "generic":
	   return providers.Generic
   default:
	   return nil
   }
}

func (providers *Providers) GetUser(provider string) (constants.Claims, error) {
	var user constants.Claims

	// Get the user from the provider
   switch provider {
   case "github":
	   if providers.Github == nil {
		   log.Debug().Msg("Github provider not configured")
		   return user, nil
	   }
	   client := providers.Github.GetClient()
	   log.Debug().Msg("Got client from github")
	   user, err := GetGithubUser(client)
	   if err != nil {
		   return user, err
	   }
	   log.Debug().Msg("Got user from github")
	   return user, nil
   case "google":
	   if providers.Google == nil {
		   log.Debug().Msg("Google provider not configured")
		   return user, nil
	   }
	   client := providers.Google.GetClient()
	   log.Debug().Msg("Got client from google")
	   user, err := GetGoogleUser(client)
	   if err != nil {
		   return user, err
	   }
	   log.Debug().Msg("Got user from google")
	   return user, nil
   case "microsoft":
	   if providers.Microsoft == nil {
		   log.Debug().Msg("Microsoft provider not configured")
		   return user, nil
	   }
	   client := providers.Microsoft.GetClient()
	   log.Debug().Msg("Got client from microsoft")
	   user, err := GetMicrosoftUser(client, providers.Config.MicrosoftUserURL)
	   if err != nil {
		   return user, err
	   }
	   log.Debug().Msg("Got user from microsoft")
	   return user, nil
   case "generic":
	   if providers.Generic == nil {
		   log.Debug().Msg("Generic provider not configured")
		   return user, nil
	   }
	   client := providers.Generic.GetClient()
	   log.Debug().Msg("Got client from generic")
	   user, err := GetGenericUser(client, providers.Config.GenericUserURL)
	   if err != nil {
		   return user, err
	   }
	   log.Debug().Msg("Got user from generic")
	   return user, nil
   default:
	   return user, nil
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
   if provider.Microsoft != nil {
	   providers = append(providers, "microsoft")
   }
   if provider.Generic != nil {
	   providers = append(providers, "generic")
   }
	return providers
}
