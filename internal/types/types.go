package types

import (
	"time"
	"tinyauth/internal/oauth"
)

// User is the struct for a user
type User struct {
	Username   string
	Password   string
	TotpSecret string
}

// Users is a list of users
type Users []User

// OAuthProviders is the struct for the OAuth providers
type OAuthProviders struct {
	Github    *oauth.OAuth
	Google    *oauth.OAuth
	Microsoft *oauth.OAuth
}

// SessionCookie is the cookie for the session (exculding the expiry)
type SessionCookie struct {
	Username    string
	Provider    string
	TotpPending bool
	RedirectURI string
}

// TinyauthLabels is the labels for the tinyauth container
type TinyauthLabels struct {
	OAuthWhitelist []string
	Users          []string
	Allowed        string
	Headers        map[string]string
}

// UserContext is the context for the user
type UserContext struct {
	Username    string
	IsLoggedIn  bool
	OAuth       bool
	Provider    string
	TotpPending bool
}

// LoginAttempt tracks information about login attempts for rate limiting
type LoginAttempt struct {
	FailedAttempts int
	LastAttempt    time.Time
	LockedUntil    time.Time
}
