package config

// Version information, set at build time

var Version = "development"
var CommitHash = "n/a"
var BuildTimestamp = "n/a"

// Cookie name templates

var SessionCookieName = "tinyauth-session"
var CSRFCookieName = "tinyauth-csrf"
var RedirectCookieName = "tinyauth-redirect"

// Main app config

type Config struct {
	Port                    int    `mapstructure:"port" validate:"required"`
	Address                 string `validate:"required,ip4_addr" mapstructure:"address"`
	AppURL                  string `validate:"required,url" mapstructure:"app-url"`
	Users                   string `mapstructure:"users"`
	UsersFile               string `mapstructure:"users-file"`
	SecureCookie            bool   `mapstructure:"secure-cookie"`
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
	OAuthWhitelist          string `mapstructure:"oauth-whitelist"`
	OAuthAutoRedirect       string `mapstructure:"oauth-auto-redirect" validate:"oneof=none github google generic"`
	SessionExpiry           int    `mapstructure:"session-expiry"`
	LogLevel                string `mapstructure:"log-level" validate:"oneof=trace debug info warn error fatal panic"`
	Title                   string `mapstructure:"app-title"`
	LoginTimeout            int    `mapstructure:"login-timeout"`
	LoginMaxRetries         int    `mapstructure:"login-max-retries"`
	ForgotPasswordMessage   string `mapstructure:"forgot-password-message"`
	BackgroundImage         string `mapstructure:"background-image" validate:"required"`
	LdapAddress             string `mapstructure:"ldap-address"`
	LdapBindDN              string `mapstructure:"ldap-bind-dn"`
	LdapBindPassword        string `mapstructure:"ldap-bind-password"`
	LdapBaseDN              string `mapstructure:"ldap-base-dn"`
	LdapInsecure            bool   `mapstructure:"ldap-insecure"`
	LdapSearchFilter        string `mapstructure:"ldap-search-filter"`
	ResourcesDir            string `mapstructure:"resources-dir"`
	DatabasePath            string `mapstructure:"database-path" validate:"required"`
	TrustedProxies          string `mapstructure:"trusted-proxies"`
}

// OAuth/OIDC config

type Claims struct {
	Name              string `json:"name"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Groups            any    `json:"groups"`
}

type OAuthServiceConfig struct {
	ClientID           string
	ClientSecret       string
	ClientSecretFile   string
	Scopes             []string
	RedirectURL        string
	AuthURL            string
	TokenURL           string
	UserinfoURL        string
	InsecureSkipVerify bool
	Name               string
}

// User/session related stuff

type User struct {
	Username   string
	Password   string
	TotpSecret string
}

type UserSearch struct {
	Username string
	Type     string // local, ldap or unknown
}

type SessionCookie struct {
	UUID        string
	Username    string
	Name        string
	Email       string
	Provider    string
	TotpPending bool
	OAuthGroups string
}

type UserContext struct {
	Username    string
	Name        string
	Email       string
	IsLoggedIn  bool
	OAuth       bool
	Provider    string
	TotpPending bool
	OAuthGroups string
	TotpEnabled bool
}

// API responses and queries

type UnauthorizedQuery struct {
	Username string `url:"username"`
	Resource string `url:"resource"`
	GroupErr bool   `url:"groupErr"`
	IP       string `url:"ip"`
}

type RedirectQuery struct {
	RedirectURI string `url:"redirect_uri"`
}

// Labels

type Apps struct {
	Apps map[string]App
}

type App struct {
	Config   AppConfig
	Users    AppUsers
	OAuth    AppOAuth
	IP       AppIP
	Response AppResponse
	Path     AppPath
}

type AppConfig struct {
	Domain string
}

type AppUsers struct {
	Allow string
	Block string
}

type AppOAuth struct {
	Whitelist string
	Groups    string
}

type AppIP struct {
	Allow  []string
	Block  []string
	Bypass []string
}

type AppResponse struct {
	Headers   []string
	BasicAuth AppBasicAuth
}

type AppBasicAuth struct {
	Username     string
	Password     string
	PasswordFile string
}

type AppPath struct {
	Allow string
	Block string
}

// Flags

type Providers struct {
	Providers map[string]OAuthServiceConfig
}
