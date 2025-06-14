package constants

// Claims are the OIDC supported claims (including preferd username for some reason)
type Claims struct {
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
}

// Version information
var Version = "development"
var CommitHash = "n/a"
var BuildTimestamp = "n/a"

// Cookie names
var SessionCookieName = "tinyauth-session"
var CsrfCookieName = "tinyauth-csrf"
var RedirectCookieName = "tinyauth-redirect"
