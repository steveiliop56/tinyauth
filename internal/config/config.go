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
	Port                  int    `mapstructure:"port" validate:"required"`
	Address               string `validate:"required,ip4_addr" mapstructure:"address"`
	AppURL                string `validate:"required,url" mapstructure:"app-url"`
	Users                 string `mapstructure:"users"`
	UsersFile             string `mapstructure:"users-file"`
	SecureCookie          bool   `mapstructure:"secure-cookie"`
	OAuthWhitelist        string `mapstructure:"oauth-whitelist"`
	OAuthAutoRedirect     string `mapstructure:"oauth-auto-redirect"`
	SessionExpiry         int    `mapstructure:"session-expiry"`
	LogLevel              string `mapstructure:"log-level" validate:"oneof=trace debug info warn error fatal panic"`
	Title                 string `mapstructure:"app-title"`
	LoginTimeout          int    `mapstructure:"login-timeout"`
	LoginMaxRetries       int    `mapstructure:"login-max-retries"`
	ForgotPasswordMessage string `mapstructure:"forgot-password-message"`
	BackgroundImage       string `mapstructure:"background-image" validate:"required"`
	LdapAddress           string `mapstructure:"ldap-address"`
	LdapBindDN            string `mapstructure:"ldap-bind-dn"`
	LdapBindPassword      string `mapstructure:"ldap-bind-password"`
	LdapBaseDN            string `mapstructure:"ldap-base-dn"`
	LdapInsecure          bool   `mapstructure:"ldap-insecure"`
	LdapSearchFilter      string `mapstructure:"ldap-search-filter"`
	ResourcesDir          string `mapstructure:"resources-dir"`
	DatabasePath          string `mapstructure:"database-path" validate:"required"`
	TrustedProxies        string `mapstructure:"trusted-proxies"`
	DisableAnalytics      bool   `mapstructure:"disable-analytics"`
}

// OAuth/OIDC config

type Claims struct {
	Name              string `json:"name"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Groups            any    `json:"groups"`
}

type OAuthServiceConfig struct {
	ClientID           string   `key:"client-id"`
	ClientSecret       string   `key:"client-secret"`
	ClientSecretFile   string   `key:"client-secret-file"`
	Scopes             []string `key:"scopes"`
	RedirectURL        string   `key:"redirect-url"`
	AuthURL            string   `key:"auth-url"`
	TokenURL           string   `key:"token-url"`
	UserinfoURL        string   `key:"user-info-url"`
	InsecureSkipVerify bool     `key:"insecure-skip-verify"`
	Name               string   `key:"name"`
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
	OAuthName   string
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
	OAuthName   string
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

// API server

var ApiServer = "https://api.tinyauth.app"
