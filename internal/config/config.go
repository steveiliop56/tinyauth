package config

// Version information, set at build time

var Version = "development"
var CommitHash = "development"
var BuildTimestamp = "0000-00-00T00:00:00Z"

// Cookie name templates

var SessionCookieName = "tinyauth-session"
var CSRFCookieName = "tinyauth-csrf"
var RedirectCookieName = "tinyauth-redirect"

// Main app config

type Config struct {
	AppURL            string             `description:"The base URL where the app is hosted." yaml:"appUrl"`
	LogLevel          string             `description:"Log level (trace, debug, info, warn, error)." yaml:"logLevel"`
	ResourcesDir      string             `description:"The directory where resources are stored." yaml:"resourcesDir"`
	DatabasePath      string             `description:"The path to the database file." yaml:"databasePath"`
	DisableAnalytics  bool               `description:"Disable analytics." yaml:"disableAnalytics"`
	DisableResources  bool               `description:"Disable resources server." yaml:"disableResources"`
	DisableUIWarnings bool               `description:"Disable UI warnings." yaml:"disableUIWarnings"`
	LogJSON           bool               `description:"Enable JSON formatted logs." yaml:"logJSON"`
	Server            ServerConfig       `description:"Server configuration." yaml:"server"`
	Auth              AuthConfig         `description:"Authentication configuration." yaml:"auth"`
	OAuth             OAuthConfig        `description:"OAuth configuration." yaml:"oauth"`
	UI                UIConfig           `description:"UI customization." yaml:"ui"`
	Ldap              LdapConfig         `description:"LDAP configuration." yaml:"ldap"`
	Experimental      ExperimentalConfig `description:"Experimental features, use with caution." yaml:"experimental"`
}

type ServerConfig struct {
	Port           int    `description:"The port on which the server listens." yaml:"port"`
	Address        string `description:"The address on which the server listens." yaml:"address"`
	SocketPath     string `description:"The path to the Unix socket." yaml:"socketPath"`
	TrustedProxies string `description:"Comma-separated list of trusted proxy addresses." yaml:"trustedProxies"`
}

type AuthConfig struct {
	Users           string `description:"Comma-separated list of users (username:hashed_password)." yaml:"users"`
	UsersFile       string `description:"Path to the users file." yaml:"usersFile"`
	SecureCookie    bool   `description:"Enable secure cookies." yaml:"secureCookie"`
	SessionExpiry   int    `description:"Session expiry time in seconds." yaml:"sessionExpiry"`
	LoginTimeout    int    `description:"Login timeout in seconds." yaml:"loginTimeout"`
	LoginMaxRetries int    `description:"Maximum login retries." yaml:"loginMaxRetries"`
}

type OAuthConfig struct {
	Whitelist    string                        `description:"Comma-separated list of allowed OAuth domains." yaml:"whitelist"`
	AutoRedirect string                        `description:"The OAuth provider to use for automatic redirection." yaml:"autoRedirect"`
	Providers    map[string]OAuthServiceConfig `description:"OAuth providers configuration." yaml:"providers"`
}

type UIConfig struct {
	Title                 string `description:"The title of the UI." yaml:"title"`
	ForgotPasswordMessage string `description:"Message displayed on the forgot password page." yaml:"forgotPasswordMessage"`
	BackgroundImage       string `description:"Path to the background image." yaml:"backgroundImage"`
}

type LdapConfig struct {
	Address      string `description:"LDAP server address." yaml:"address"`
	BindDN       string `description:"Bind DN for LDAP authentication." yaml:"bindDn"`
	BindPassword string `description:"Bind password for LDAP authentication." yaml:"bindPassword"`
	BaseDN       string `description:"Base DN for LDAP searches." yaml:"baseDn"`
	Insecure     bool   `description:"Allow insecure LDAP connections." yaml:"insecure"`
	SearchFilter string `description:"LDAP search filter." yaml:"searchFilter"`
}

type ExperimentalConfig struct {
	ConfigFile string `description:"Path to config file." yaml:"-"`
}

// Config loader options

const DefaultNamePrefix = "TINYAUTH_"

// OAuth/OIDC config

type Claims struct {
	Name              string `json:"name"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Groups            any    `json:"groups"`
}

type OAuthServiceConfig struct {
	ClientID         string   `description:"OAuth client ID."`
	ClientSecret     string   `description:"OAuth client secret."`
	ClientSecretFile string   `description:"Path to the file containing the OAuth client secret."`
	Scopes           []string `description:"OAuth scopes."`
	RedirectURL      string   `description:"OAuth redirect URL."`
	AuthURL          string   `description:"OAuth authorization URL."`
	TokenURL         string   `description:"OAuth token URL."`
	UserinfoURL      string   `description:"OAuth userinfo URL."`
	Insecure         bool     `description:"Allow insecure OAuth connections."`
	Name             string   `description:"Provider name in UI."`
}

var OverrideProviders = map[string]string{
	"google": "Google",
	"github": "GitHub",
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
