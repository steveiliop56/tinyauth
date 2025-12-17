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
	AppURL            string `description:"The base URL where the app is hosted."`
	LogLevel          string `description:"Log level (trace, debug, info, warn, error)."`
	ResourcesDir      string `description:"The directory where resources are stored."`
	DatabasePath      string `description:"The path to the database file."`
	DisableAnalytics  bool   `description:"Disable analytics."`
	DisableResources  bool   `description:"Disable resources server."`
	DisableUIWarnings bool   `description:"Disable UI warnings."`
	Server            ServerConfig
	Auth              AuthConfig
	OAuth             OAuthConfig
	UI                UIConfig
	Ldap              LdapConfig
}

type ServerConfig struct {
	Port           int    `description:"The port on which the server listens."`
	Address        string `description:"The address on which the server listens."`
	SocketPath     string `description:"The path to the Unix socket."`
	TrustedProxies string `description:"Comma-separated list of trusted proxy addresses."`
}

type AuthConfig struct {
	Users           string `description:"Comma-separated list of users (username:hashed_password)."`
	UsersFile       string `description:"Path to the users file."`
	SecureCookie    bool   `description:"Enable secure cookies."`
	SessionExpiry   int    `description:"Session expiry time in seconds."`
	LoginTimeout    int    `description:"Login timeout in seconds."`
	LoginMaxRetries int    `description:"Maximum login retries."`
}

type OAuthConfig struct {
	Whitelist    string `description:"Comma-separated list of allowed OAuth domains."`
	AutoRedirect string `description:"The OAuth provider to use for automatic redirection."`
	Providers    map[string]OAuthServiceConfig
}

type UIConfig struct {
	Title                 string `description:"The title of the UI."`
	ForgotPasswordMessage string `description:"Message displayed on the forgot password page."`
	BackgroundImage       string `description:"Path to the background image."`
}

type LdapConfig struct {
	Address      string `description:"LDAP server address."`
	BindDN       string `description:"Bind DN for LDAP authentication."`
	BindPassword string `description:"Bind password for LDAP authentication."`
	BaseDN       string `description:"Base DN for LDAP searches."`
	Insecure     bool   `description:"Allow insecure LDAP connections."`
	SearchFilter string `description:"LDAP search filter."`
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
