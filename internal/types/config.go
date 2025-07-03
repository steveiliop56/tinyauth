package types

// Config is the configuration for the tinyauth server
type Config struct {
	Port                    int    `mapstructure:"port" validate:"required"`
	Address                 string `validate:"required,ip4_addr" mapstructure:"address"`
	Secret                  string `validate:"required,len=32" mapstructure:"secret"`
	SecretFile              string `mapstructure:"secret-file"`
	AppURL                  string `validate:"required,url" mapstructure:"app-url"`
	Users                   string `mapstructure:"users"`
	UsersFile               string `mapstructure:"users-file"`
	CookieSecure            bool   `mapstructure:"cookie-secure"`
	GithubClientId          string `mapstructure:"github-client-id"`
	GithubClientSecret      string `mapstructure:"github-client-secret"`
	GithubClientSecretFile  string `mapstructure:"github-client-secret-file"`
	GoogleClientId          string `mapstructure:"google-client-id"`
	GoogleClientSecret      string `mapstructure:"google-client-secret"`
	GoogleClientSecretFile  string `mapstructure:"google-client-secret-file"`
	GenericClientId         string `mapstructure:"generic-client-id"`
	GenericClientSecret     string `mapstructure:"generic-client-secret"`
	GenericClientSecretFile string `mapstructure:"generic-client-secret-file"`
	GenericScopes           string `mapstructure:"generic-scopes"`
	GenericAuthURL          string `mapstructure:"generic-auth-url"`
	GenericTokenURL         string `mapstructure:"generic-token-url"`
	GenericUserURL          string `mapstructure:"generic-user-url"`
	GenericName             string `mapstructure:"generic-name"`
	GenericSkipSSL          bool   `mapstructure:"generic-skip-ssl"`
	DisableContinue         bool   `mapstructure:"disable-continue"`
	OAuthWhitelist          string `mapstructure:"oauth-whitelist"`
	OAuthAutoRedirect       string `mapstructure:"oauth-auto-redirect" validate:"oneof=none github google generic"`
	SessionExpiry           int    `mapstructure:"session-expiry"`
	LogLevel                int8   `mapstructure:"log-level" validate:"min=-1,max=5"`
	Title                   string `mapstructure:"app-title"`
	EnvFile                 string `mapstructure:"env-file"`
	LoginTimeout            int    `mapstructure:"login-timeout"`
	LoginMaxRetries         int    `mapstructure:"login-max-retries"`
	FogotPasswordMessage    string `mapstructure:"forgot-password-message" validate:"required"`
	BackgroundImage         string `mapstructure:"background-image" validate:"required"`
}

// Server configuration
type HandlersConfig struct {
	AppURL                string
	Domain                string
	CookieSecure          bool
	DisableContinue       bool
	GenericName           string
	Title                 string
	ForgotPasswordMessage string
	BackgroundImage       string
	OAuthAutoRedirect     string
	CsrfCookieName        string
	RedirectCookieName    string
}

// OAuthConfig is the configuration for the providers
type OAuthConfig struct {
	GithubClientId      string
	GithubClientSecret  string
	GoogleClientId      string
	GoogleClientSecret  string
	GenericClientId     string
	GenericClientSecret string
	GenericScopes       []string
	GenericAuthURL      string
	GenericTokenURL     string
	GenericUserURL      string
	GenericSkipSSL      bool
	AppURL              string
}

// ServerConfig is the configuration for the server
type ServerConfig struct {
	Port    int
	Address string
}

// AuthConfig is the configuration for the auth service
type AuthConfig struct {
	Users             Users
	OauthWhitelist    string
	SessionExpiry     int
	CookieSecure      bool
	Domain            string
	LoginTimeout      int
	LoginMaxRetries   int
	SessionCookieName string
	HMACSecret        string
	EncryptionSecret  string
}

// HooksConfig is the configuration for the hooks service
type HooksConfig struct {
	Domain string
}

// OAuthLabels is a list of labels that can be used in a tinyauth protected container
type OAuthLabels struct {
	Whitelist string
	Groups    string
}

// Basic auth labels for a tinyauth protected container
type BasicLabels struct {
	User     string
	Password string
}

// IP labels for a tinyauth protected container
type IPLabels struct {
	Allow []string
	Block []string
}

// Labels is a struct that contains the labels for a tinyauth protected container
type Labels struct {
	Users   string
	Allowed string
	Headers []string
	Domain  string
	Basic   BasicLabels
	OAuth   OAuthLabels
	IP      IPLabels
}
