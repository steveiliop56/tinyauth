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
	Name        string
	Email       string
	Provider    string
	TotpPending bool
	OAuthGroups string
}

// UserContext is the context for the user
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

// LoginAttempt tracks information about login attempts for rate limiting
type LoginAttempt struct {
	FailedAttempts int
	LastAttempt    time.Time
	LockedUntil    time.Time
}
