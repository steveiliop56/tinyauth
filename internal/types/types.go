package types

import "tinyauth/internal/oauth"

type LoginQuery struct {
	RedirectURI string `url:"redirect_uri"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type User struct {
	Email    string
	Password string
}

type Users []User

type Config struct {
	Port                int    `validate:"number" mapstructure:"port"`
	Address             string `mapstructure:"address, ip4_addr"`
	Secret              string `validate:"required,len=32" mapstructure:"secret"`
	AppURL              string `validate:"required,url" mapstructure:"app-url"`
	Users               string `mapstructure:"users"`
	UsersFile           string `mapstructure:"users-file"`
	CookieSecure        bool   `mapstructure:"cookie-secure"`
	GithubClientId      string `mapstructure:"github-client-id"`
	GithubClientSecret  string `mapstructure:"github-client-secret"`
	GoogleClientId      string `mapstructure:"google-client-id"`
	GoogleClientSecret  string `mapstructure:"google-client-secret"`
	GenericClientId     string `mapstructure:"generic-client-id"`
	GenericClientSecret string `mapstructure:"generic-client-secret"`
	GenericScopes       string `mapstructure:"generic-scopes"`
	GenericAuthURL      string `mapstructure:"generic-auth-url"`
	GenericTokenURL     string `mapstructure:"generic-token-url"`
	GenericUserInfoURL  string `mapstructure:"generic-user-info-url"`
	DisableContinue     bool   `mapstructure:"disable-continue"`
}

type UserContext struct {
	Email      string
	IsLoggedIn bool
	OAuth      bool
	Provider   string
}

type APIConfig struct {
	Port            int
	Address         string
	Secret          string
	AppURL          string
	CookieSecure    bool
	DisableContinue bool
}

type OAuthConfig struct {
	GithubClientId      string
	GithubClientSecret  string
	GoogleClientId      string
	GoogleClientSecret  string
	GenericClientId     string
	GenericClientSecret string
	GenericScopes       string
	GenericAuthURL      string
	GenericTokenURL     string
	GenericUserInfoURL  string
	AppURL              string
}

type OAuthRequest struct {
	Provider string `uri:"provider" binding:"required"`
}

type OAuthProviders struct {
	Github    *oauth.OAuth
	Google    *oauth.OAuth
	Microsoft *oauth.OAuth
}
