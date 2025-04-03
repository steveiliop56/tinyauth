package auth

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"tinyauth/internal/docker"
	"tinyauth/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

func NewAuth(config types.AuthConfig, docker *docker.Docker) *Auth {
	return &Auth{
		Docker: docker,
		Config: config,
	}
}

type Auth struct {
	Docker *docker.Docker
	Config types.AuthConfig
}

func (auth *Auth) GetUser(username string) *types.User {
	// Loop through users and return the user if the username matches
	for _, user := range auth.Config.Users {
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

func (auth *Auth) EmailWhitelisted(emailSrc string) bool {
	// If the whitelist is empty, allow all emails
	if len(auth.Config.OAuthWhitelist) == 0 {
		return true
	}

	// Loop through the whitelist and return true if the email matches
	for _, email := range auth.Config.OAuthWhitelist {
		if email == emailSrc {
			return true
		}
	}

	// If no emails match, return false
	return false
}

func (auth *Auth) GetCookieStore() *sessions.CookieStore {
	// Create a new cookie store
	store := sessions.NewCookieStore([]byte(auth.Config.Secret))

	// Configure the cookie store
	store.Options = &sessions.Options{
		Path:     "/",
		Domain:   fmt.Sprintf(".%s", auth.Config.Domain),
		Secure:   auth.Config.CookieSecure,
		MaxAge:   auth.Config.SessionExpiry,
		HttpOnly: true,
	}

	// Set the cookie store
	return store
}

func (auth *Auth) CreateSessionCookie(c *gin.Context, data *types.SessionCookie) error {
	log.Debug().Msg("Creating session cookie")

	// Get cookie store
	store := auth.GetCookieStore()

	// Get session
	sessions, err := store.Get(c.Request, "tinyauth")

	if err != nil {
		return err
	}

	log.Debug().Msg("Setting session cookie")

	// Calculate expiry
	var sessionExpiry int

	if data.TotpPending {
		sessionExpiry = 3600
	} else {
		sessionExpiry = auth.Config.SessionExpiry
	}

	// Set data
	sessions.Values["username"] = data.Username
	sessions.Values["provider"] = data.Provider
	sessions.Values["expiry"] = time.Now().Add(time.Duration(sessionExpiry) * time.Second).Unix()
	sessions.Values["totpPending"] = data.TotpPending

	// Save session
	err = sessions.Save(c.Request, c.Writer)

	if err != nil {
		return err
	}

	// Return nil
	return nil
}

func (auth *Auth) DeleteSessionCookie(c *gin.Context) error {
	log.Debug().Msg("Deleting session cookie")

	// Get cookie store
	store := auth.GetCookieStore()

	// Get session
	sessions, err := store.Get(c.Request, "tinyauth")

	if err != nil {
		return err
	}

	// Clear session
	for key := range sessions.Values {
		delete(sessions.Values, key)
	}

	// Save session
	err = sessions.Save(c.Request, c.Writer)

	if err != nil {
		return err
	}

	// Return nil
	return nil
}

func (auth *Auth) GetSessionCookie(c *gin.Context) (types.SessionCookie, error) {
	log.Debug().Msg("Getting session cookie")

	// Get cookie store
	store := auth.GetCookieStore()

	// Get session
	sessions, err := store.Get(c.Request, "tinyauth")

	if err != nil {
		return types.SessionCookie{}, err
	}

	// Get data
	cookieUsername := sessions.Values["username"]
	cookieProvider := sessions.Values["provider"]
	cookieExpiry := sessions.Values["expiry"]
	cookieTotpPending := sessions.Values["totpPending"]

	// Convert interfaces to correct types
	username, usernameOk := cookieUsername.(string)
	provider, providerOk := cookieProvider.(string)
	expiry, expiryOk := cookieExpiry.(int64)
	totpPending, totpPendingOk := cookieTotpPending.(bool)

	// Check if the cookie is invalid
	if !usernameOk || !providerOk || !expiryOk || !totpPendingOk {
		log.Warn().Msg("Session cookie invalid")
		return types.SessionCookie{}, nil
	}

	// Check if the cookie has expired
	if time.Now().Unix() > expiry {
		log.Warn().Msg("Session cookie expired")

		// If it has, delete it
		auth.DeleteSessionCookie(c)

		// Return empty cookie
		return types.SessionCookie{}, nil
	}

	log.Debug().Str("username", username).Str("provider", provider).Int64("expiry", expiry).Bool("totpPending", totpPending).Msg("Parsed cookie")

	// Return the cookie
	return types.SessionCookie{
		Username:    username,
		Provider:    provider,
		TotpPending: totpPending,
	}, nil
}

func (auth *Auth) UserAuthConfigured() bool {
	// If there are users, return true
	return len(auth.Config.Users) > 0
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
