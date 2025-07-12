package constants

// Claims are the OIDC supported claims (prefered username is included for convinience)
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

// Base cookie names
var SessionCookieName = "tinyauth-session"
var CsrfCookieName = "tinyauth-csrf"
var RedirectCookieName = "tinyauth-redirect"
