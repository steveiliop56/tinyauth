package config

type Claims struct {
	Name              string `json:"name"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Groups            any    `json:"groups"`
}

var Version = "development"
var CommitHash = "n/a"
var BuildTimestamp = "n/a"

var SessionCookieName = "tinyauth-session"
var CSRFCookieName = "tinyauth-csrf"
var RedirectCookieName = "tinyauth-redirect"

type Config struct {
	Port                    int    `mapstructure:"port" validate:"required"`
	Address                 string `validate:"required,ip4_addr" mapstructure:"address"`
	Secret                  string `validate:"required,len=32" mapstructure:"secret"`
	SecretFile              string `mapstructure:"secret-file"`
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
	DisableContinue         bool   `mapstructure:"disable-continue"`
	OAuthWhitelist          string `mapstructure:"oauth-whitelist"`
	OAuthAutoRedirect       string `mapstructure:"oauth-auto-redirect" validate:"oneof=none github google generic"`
	SessionExpiry           int    `mapstructure:"session-expiry"`
	LogLevel                string `mapstructure:"log-level" validate:"oneof=trace debug info warn error fatal panic"`
	Title                   string `mapstructure:"app-title"`
	LoginTimeout            int    `mapstructure:"login-timeout"`
	LoginMaxRetries         int    `mapstructure:"login-max-retries"`
	FogotPasswordMessage    string `mapstructure:"forgot-password-message"`
	BackgroundImage         string `mapstructure:"background-image" validate:"required"`
	LdapAddress             string `mapstructure:"ldap-address"`
	LdapBindDN              string `mapstructure:"ldap-bind-dn"`
	LdapBindPassword        string `mapstructure:"ldap-bind-password"`
	LdapBaseDN              string `mapstructure:"ldap-base-dn"`
	LdapInsecure            bool   `mapstructure:"ldap-insecure"`
	LdapSearchFilter        string `mapstructure:"ldap-search-filter"`
	ResourcesDir            string `mapstructure:"resources-dir"`
}

type OAuthLabels struct {
	Whitelist string
	Groups    string
}

type BasicLabels struct {
	Username string
	Password PassowrdLabels
}

type PassowrdLabels struct {
	Plain string
	File  string
}

type IPLabels struct {
	Allow  []string
	Block  []string
	Bypass []string
}

type Labels struct {
	Users   string
	Allowed string
	Headers []string
	Domain  []string
	Basic   BasicLabels
	OAuth   OAuthLabels
	IP      IPLabels
}

type OAuthServiceConfig struct {
	ClientID           string
	ClientSecret       string
	Scopes             []string
	RedirectURL        string
	AuthURL            string
	TokenURL           string
	UserinfoURL        string
	InsecureSkipVerify bool
}

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

type UnauthorizedQuery struct {
	Username string `url:"username"`
	Resource string `url:"resource"`
	GroupErr bool   `url:"groupErr"`
	IP       string `url:"ip"`
}

type RedirectQuery struct {
	RedirectURI string `url:"redirect_uri"`
}
