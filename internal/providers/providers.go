package providers

import (
	"fmt"
	"tinyauth/internal/oauth"
	"tinyauth/internal/types"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
	"github.com/golang-jwt/jwt/v5"
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
		})

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
		})

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
		})

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

func (providers *Providers) GetUser(providerName string, token *oauth2.Token) (string, map[string]interface{}, error) {
	switch providerName {
	case "github":
		if providers.Github == nil {
			log.Debug().Msg("Github provider not configured")
			return "", nil, errors.New("github provider not configured")
		}
		client := providers.Github.Config.Client(providers.Github.Context, token)
		email, err := GetGithubEmail(client)
		return email, nil, err
	case "google":
		if providers.Google == nil {
			log.Debug().Msg("Google provider not configured")
			return "", nil, errors.New("google provider not configured")
		}
		client := providers.Google.Config.Client(providers.Google.Context, token)
		email, err := GetGoogleEmail(client)
        claims := map[string]interface{}{"email": email}
		return email, claims, err
	case "generic":
		if providers.Generic == nil {
			log.Debug().Msg("Generic provider not configured")
			return "", nil, errors.New("generic provider not configured")
		}

		idTokenInterface := token.Extra("id_token")
		if idTokenInterface == nil {
			log.Error().Msg("ID token not found in token response for generic provider")
			return "", nil, errors.New("id_token not found in token response")
		}

		idTokenString, ok := idTokenInterface.(string)
		if !ok {
			log.Error().Msg("id_token in token response is not a string")
			return "", nil, errors.New("id_token is not a string")
		}

		log.Debug().Msg("Parsing ID token from generic provider")

		// Should change to verify the signature using keys from JWKS endpoint.
		parsedToken, _, err := new(jwt.Parser).ParseUnverified(idTokenString, jwt.MapClaims{})
		if err != nil {
			log.Error().Err(err).Msg("Failed to parse ID token")
			return "", nil, fmt.Errorf("failed to parse id_token: %w", err)
		}

		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		if !ok {
			log.Error().Msg("Failed to assert claims as jwt.MapClaims")
			return "", nil, errors.New("invalid claims format in id_token")
		}

		// Extract a user identifier (e.g., email or sub) for whitelisting
		identifier := ""
		if email, ok := claims["email"].(string); ok && email != "" {
			identifier = email
		} else if sub, ok := claims["sub"].(string); ok && sub != "" {
			identifier = sub // Fallback to subject claim
		} else {
            log.Warn().Interface("claims", claims).Msg("Could not find 'email' or 'sub' claim for identifier in ID token")
			return "", claims, errors.New("cannot determine user identifier from id_token claims")
		}

		log.Debug().Str("identifier", identifier).Msg("Extracted user info from generic ID token")
		return identifier, claims, nil

	default:
		return "", nil, errors.New("unknown provider")
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
