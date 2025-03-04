package types

import "tinyauth/internal/oauth"

// LoginQuery is the query parameters for the login endpoint
type LoginQuery struct {
	RedirectURI string `url:"redirect_uri"`
}

// LoginRequest is the request body for the login endpoint
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// User is the struct for a user
type User struct {
	Username   string
	Password   string
	TotpSecret string
}

// Users is a list of users
type Users []User

// Config is the configuration for the tinyauth server
type Config struct {
	Port                      int    `mapstructure:"port" validate:"required"`
	Address                   string `validate:"required,ip4_addr" mapstructure:"address"`
	Secret                    string `validate:"required,len=32" mapstructure:"secret"`
	SecretFile                string `mapstructure:"secret-file"`
	AppURL                    string `validate:"required,url" mapstructure:"app-url"`
	Users                     string `mapstructure:"users"`
	UsersFile                 string `mapstructure:"users-file"`
	CookieSecure              bool   `mapstructure:"cookie-secure"`
	GithubClientId            string `mapstructure:"github-client-id"`
	GithubClientSecret        string `mapstructure:"github-client-secret"`
	GithubClientSecretFile    string `mapstructure:"github-client-secret-file"`
	GoogleClientId            string `mapstructure:"google-client-id"`
	GoogleClientSecret        string `mapstructure:"google-client-secret"`
	GoogleClientSecretFile    string `mapstructure:"google-client-secret-file"`
	TailscaleClientId         string `mapstructure:"tailscale-client-id"`
	TailscaleClientSecret     string `mapstructure:"tailscale-client-secret"`
	TailscaleClientSecretFile string `mapstructure:"tailscale-client-secret-file"`
	GenericClientId           string `mapstructure:"generic-client-id"`
	GenericClientSecret       string `mapstructure:"generic-client-secret"`
	GenericClientSecretFile   string `mapstructure:"generic-client-secret-file"`
	GenericScopes             string `mapstructure:"generic-scopes"`
	GenericAuthURL            string `mapstructure:"generic-auth-url"`
	GenericTokenURL           string `mapstructure:"generic-token-url"`
	GenericUserURL            string `mapstructure:"generic-user-url"`
	GenericName               string `mapstructure:"generic-name"`
	DisableContinue           bool   `mapstructure:"disable-continue"`
	OAuthWhitelist            string `mapstructure:"oauth-whitelist"`
	SessionExpiry             int    `mapstructure:"session-expiry"`
	LogLevel                  int8   `mapstructure:"log-level" validate:"min=-1,max=5"`
	Title                     string `mapstructure:"app-title"`
}

// UserContext is the context for the user
type UserContext struct {
	Username   string
	IsLoggedIn bool
	OAuth      bool
	Provider   string
}

// APIConfig is the configuration for the API
type APIConfig struct {
	Port            int
	Address         string
	Secret          string
	AppURL          string
	CookieSecure    bool
	SessionExpiry   int
	DisableContinue bool
	GenericName     string
	Title           string
}

// OAuthConfig is the configuration for the providers
type OAuthConfig struct {
	GithubClientId        string
	GithubClientSecret    string
	GoogleClientId        string
	GoogleClientSecret    string
	TailscaleClientId     string
	TailscaleClientSecret string
	GenericClientId       string
	GenericClientSecret   string
	GenericScopes         []string
	GenericAuthURL        string
	GenericTokenURL       string
	GenericUserURL        string
	AppURL                string
}

// OAuthRequest is the request for the OAuth endpoint
type OAuthRequest struct {
	Provider string `uri:"provider" binding:"required"`
}

// OAuthProviders is the struct for the OAuth providers
type OAuthProviders struct {
	Github    *oauth.OAuth
	Google    *oauth.OAuth
	Microsoft *oauth.OAuth
}

// UnauthorizedQuery is the query parameters for the unauthorized endpoint
type UnauthorizedQuery struct {
	Username string `url:"username"`
	Resource string `url:"resource"`
}

// SessionCookie is the cookie for the session (exculding the expiry)
type SessionCookie struct {
	Username string
	Provider string
}

// TinyauthLabels is the labels for the tinyauth container
type TinyauthLabels struct {
	OAuthWhitelist []string
	Users          []string
	Allowed        string
}

// TailscaleQuery is the query parameters for the tailscale endpoint
type TailscaleQuery struct {
	Code int `url:"code"`
}

// Proxy is the uri parameters for the proxy endpoint
type Proxy struct {
	Proxy string `uri:"proxy" binding:"required"`
}

// Status response
type Status struct {
	Status              int      `json:"status"`
	Message             string   `json:"message"`
	IsLoggedIn          bool     `json:"isLoggedIn"`
	Username            string   `json:"username"`
	Provider            string   `json:"provider"`
	Oauth               bool     `json:"oauth"`
	ConfiguredProviders []string `json:"configuredProviders"`
	DisableContinue     bool     `json:"disableContinue"`
	Title               string   `json:"title"`
	GenericName         string   `json:"genericName"`
}
