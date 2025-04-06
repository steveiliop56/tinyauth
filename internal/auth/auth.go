package auth

import (
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"tinyauth/internal/docker"
	"tinyauth/internal/types"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

func NewAuth(docker *docker.Docker, userList types.Users, oauthWhitelist []string, sessionExpiry int, loginTimeout int, loginMaxRetries int) *Auth {
	return &Auth{
		Docker:         docker,
		Users:          userList,
		OAuthWhitelist: oauthWhitelist,
		SessionExpiry:  sessionExpiry,
		LoginTimeout:   loginTimeout,
		LoginMaxRetries: loginMaxRetries,
		LoginAttempts:  make(map[string]*LoginAttempt),
	}
}

// LoginAttempt tracks information about login attempts for rate limiting
type LoginAttempt struct {
	FailedAttempts int
	LastAttempt    time.Time
	LockedUntil    time.Time
}

type Auth struct {
	Users          types.Users
	Docker         *docker.Docker
	OAuthWhitelist []string
	SessionExpiry  int
	LoginTimeout   int
	LoginMaxRetries int
	LoginAttempts  map[string]*LoginAttempt // Map of username/IP to login attempts
	LoginMutex     sync.RWMutex            // Mutex to protect the LoginAttempts map
}

func (auth *Auth) GetUser(username string) *types.User {
	// Loop through users and return the user if the username matches
	for _, user := range auth.Users {
		if user.Username == username {
			return &user
		}
	}
	return nil
}

func (auth *Auth) CheckPassword(user types.User, password string) bool {
	// Compare the hashed password with the password provided
	return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) == nil
}

// IsAccountLocked checks if a username or IP is locked due to too many failed login attempts
func (auth *Auth) IsAccountLocked(identifier string) (bool, int) {
	auth.LoginMutex.RLock()
	defer auth.LoginMutex.RUnlock()
	
	// Return false if rate limiting is not configured
	if auth.LoginMaxRetries <= 0 || auth.LoginTimeout <= 0 {
		return false, 0
	}
	
	// Check if the identifier exists in the map
	attempt, exists := auth.LoginAttempts[identifier]
	if !exists {
		return false, 0
	}
	
	// If account is locked, check if lock time has expired
	if attempt.LockedUntil.After(time.Now()) {
		// Calculate remaining lockout time in seconds
		remaining := int(time.Until(attempt.LockedUntil).Seconds())
		return true, remaining
	}
	
	// Lock has expired
	return false, 0
}

// RecordLoginAttempt records a login attempt for rate limiting
func (auth *Auth) RecordLoginAttempt(identifier string, success bool) {
	// Skip if rate limiting is not configured
	if auth.LoginMaxRetries <= 0 || auth.LoginTimeout <= 0 {
		return
	}
	
	auth.LoginMutex.Lock()
	defer auth.LoginMutex.Unlock()
	
	// Get current attempt record or create a new one
	attempt, exists := auth.LoginAttempts[identifier]
	if !exists {
		attempt = &LoginAttempt{}
		auth.LoginAttempts[identifier] = attempt
	}
	
	// Update last attempt time
	attempt.LastAttempt = time.Now()
	
	// If successful login, reset failed attempts
	if success {
		attempt.FailedAttempts = 0
		attempt.LockedUntil = time.Time{} // Reset lock time
		return
	}
	
	// Increment failed attempts
	attempt.FailedAttempts++
	
	// If max retries reached, lock the account
	if attempt.FailedAttempts >= auth.LoginMaxRetries {
		attempt.LockedUntil = time.Now().Add(time.Duration(auth.LoginTimeout) * time.Second)
		log.Warn().Str("identifier", identifier).Int("timeout", auth.LoginTimeout).Msg("Account locked due to too many failed login attempts")
	}
}

func (auth *Auth) EmailWhitelisted(emailSrc string) bool {
	// If the whitelist is empty, allow all emails
	if len(auth.OAuthWhitelist) == 0 {
		return true
	}

	// Loop through the whitelist and return true if the email matches
	for _, email := range auth.OAuthWhitelist {
		if email == emailSrc {
			return true
		}
	}

	// If no emails match, return false
	return false
}

func (auth *Auth) CreateSessionCookie(c *gin.Context, data *types.SessionCookie) {
	log.Debug().Msg("Creating session cookie")

	// Get session
	sessions := sessions.Default(c)

	log.Debug().Msg("Setting session cookie")

	// Calculate expiry
	var sessionExpiry int

	if data.TotpPending {
		sessionExpiry = 3600
	} else {
		sessionExpiry = auth.SessionExpiry
	}

	// Set data
	sessions.Set("username", data.Username)
	sessions.Set("provider", data.Provider)
	sessions.Set("expiry", time.Now().Add(time.Duration(sessionExpiry)*time.Second).Unix())
	sessions.Set("totpPending", data.TotpPending)

	// Save session
	sessions.Save()
}

func (auth *Auth) DeleteSessionCookie(c *gin.Context) {
	log.Debug().Msg("Deleting session cookie")

	// Get session
	sessions := sessions.Default(c)

	// Clear session
	sessions.Clear()

	// Save session
	sessions.Save()
}

func (auth *Auth) GetSessionCookie(c *gin.Context) types.SessionCookie {
	log.Debug().Msg("Getting session cookie")

	// Get session
	sessions := sessions.Default(c)

	// Get data
	cookieUsername := sessions.Get("username")
	cookieProvider := sessions.Get("provider")
	cookieExpiry := sessions.Get("expiry")
	cookieTotpPending := sessions.Get("totpPending")

	// Convert interfaces to correct types
	username, usernameOk := cookieUsername.(string)
	provider, providerOk := cookieProvider.(string)
	expiry, expiryOk := cookieExpiry.(int64)
	totpPending, totpPendingOk := cookieTotpPending.(bool)

	// Check if the cookie is invalid
	if !usernameOk || !providerOk || !expiryOk || !totpPendingOk {
		log.Warn().Msg("Session cookie invalid")
		return types.SessionCookie{}
	}

	// Check if the cookie has expired
	if time.Now().Unix() > expiry {
		log.Warn().Msg("Session cookie expired")

		// If it has, delete it
		auth.DeleteSessionCookie(c)

		// Return empty cookie
		return types.SessionCookie{}
	}

	log.Debug().Str("username", username).Str("provider", provider).Int64("expiry", expiry).Bool("totpPending", totpPending).Msg("Parsed cookie")

	// Return the cookie
	return types.SessionCookie{
		Username:    username,
		Provider:    provider,
		TotpPending: totpPending,
	}
}

func (auth *Auth) UserAuthConfigured() bool {
	// If there are users, return true
	return len(auth.Users) > 0
}

func (auth *Auth) ResourceAllowed(c *gin.Context, context types.UserContext) (bool, error) {
	// Get headers
	host := c.Request.Header.Get("X-Forwarded-Host")

	// Get app id
	appId := strings.Split(host, ".")[0]

	// Get the container labels
	labels, err := auth.Docker.GetLabels(appId)

	// If there is an error, return false
	if err != nil {
		return false, err
	}

	// Check if oauth is allowed
	if context.OAuth {
		if len(labels.OAuthWhitelist) == 0 {
			return true, nil
		}
		log.Debug().Msg("Checking OAuth whitelist")
		if slices.Contains(labels.OAuthWhitelist, context.Username) {
			return true, nil
		}
	}

	// Check if user is allowed
	if len(labels.Users) != 0 {
		log.Debug().Msg("Checking users")
		if slices.Contains(labels.Users, context.Username) {
			return true, nil
		}
	}

	// Not allowed
	return false, nil
}

func (auth *Auth) AuthEnabled(c *gin.Context) (bool, error) {
	// Get headers
	uri := c.Request.Header.Get("X-Forwarded-Uri")
	host := c.Request.Header.Get("X-Forwarded-Host")

	// Get app id
	appId := strings.Split(host, ".")[0]

	// Get the container labels
	labels, err := auth.Docker.GetLabels(appId)

	// If there is an error, auth enabled
	if err != nil {
		return true, err
	}

	// Check if the allowed label is empty
	if labels.Allowed == "" {
		// Auth enabled
		return true, nil
	}

	// Compile regex
	regex, err := regexp.Compile(labels.Allowed)

	// If there is an error, invalid regex, auth enabled
	if err != nil {
		log.Warn().Err(err).Msg("Invalid regex")
		return true, err
	}

	// Check if the uri matches the regex
	if regex.MatchString(uri) {
		// Auth disabled
		return false, nil
	}

	// Auth enabled
	return true, nil
}

func (auth *Auth) GetBasicAuth(c *gin.Context) *types.User {
	// Get the Authorization header
	username, password, ok := c.Request.BasicAuth()

	// If not ok, return an empty user
	if !ok {
		return nil
	}

	// Return the user
	return &types.User{
		Username: username,
		Password: password,
	}
}
