package service

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/repository"
	"github.com/steveiliop56/tinyauth/internal/utils"
	"github.com/steveiliop56/tinyauth/internal/utils/tlog"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type LoginAttempt struct {
	FailedAttempts int
	LastAttempt    time.Time
	LockedUntil    time.Time
}

type AuthServiceConfig struct {
	Users              []config.User
	OauthWhitelist     []string
	SessionExpiry      int
	SessionMaxLifetime int
	SecureCookie       bool
	CookieDomain       string
	LoginTimeout       int
	LoginMaxRetries    int
	SessionCookieName  string
	IP                 config.IPConfig
}

type AuthService struct {
	config        AuthServiceConfig
	docker        *DockerService
	loginAttempts map[string]*LoginAttempt
	loginMutex    sync.RWMutex
	ldap          *LdapService
	queries       *repository.Queries
}

func NewAuthService(config AuthServiceConfig, docker *DockerService, ldap *LdapService, queries *repository.Queries) *AuthService {
	return &AuthService{
		config:        config,
		docker:        docker,
		loginAttempts: make(map[string]*LoginAttempt),
		ldap:          ldap,
		queries:       queries,
	}
}

func (auth *AuthService) Init() error {
	return nil
}

func (auth *AuthService) SearchUser(username string) config.UserSearch {
	if auth.GetLocalUser(username).Username != "" {
		return config.UserSearch{
			Username: username,
			Type:     "local",
		}
	}

	if auth.ldap != nil {
		userDN, err := auth.ldap.GetUserDN(username)

		if err != nil {
			tlog.App.Warn().Err(err).Str("username", username).Msg("Failed to search for user in LDAP")
			return config.UserSearch{
				Type: "unknown",
			}
		}

		return config.UserSearch{
			Username: userDN,
			Type:     "ldap",
		}
	}

	return config.UserSearch{
		Type: "unknown",
	}
}

func (auth *AuthService) VerifyUser(search config.UserSearch, password string) bool {
	switch search.Type {
	case "local":
		user := auth.GetLocalUser(search.Username)
		return auth.CheckPassword(user, password)
	case "ldap":
		if auth.ldap != nil {
			err := auth.ldap.Bind(search.Username, password)
			if err != nil {
				tlog.App.Warn().Err(err).Str("username", search.Username).Msg("Failed to bind to LDAP")
				return false
			}

			err = auth.ldap.BindService(true)
			if err != nil {
				tlog.App.Error().Err(err).Msg("Failed to rebind with service account after user authentication")
				return false
			}

			return true
		}
	default:
		tlog.App.Debug().Str("type", search.Type).Msg("Unknown user type for authentication")
		return false
	}

	tlog.App.Warn().Str("username", search.Username).Msg("User authentication failed")
	return false
}

func (auth *AuthService) GetLocalUser(username string) config.User {
	for _, user := range auth.config.Users {
		if user.Username == username {
			return user
		}
	}

	tlog.App.Warn().Str("username", username).Msg("Local user not found")
	return config.User{}
}

func (auth *AuthService) GetLdapUser(userDN string) (config.LdapUser, error) {
	groups, err := auth.ldap.GetUserGroups(userDN)

	if err != nil {
		return config.LdapUser{}, err
	}

	return config.LdapUser{
		DN:     userDN,
		Groups: groups,
	}, nil
}

func (auth *AuthService) CheckPassword(user config.User, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) == nil
}

func (auth *AuthService) IsAccountLocked(identifier string) (bool, int) {
	auth.loginMutex.RLock()
	defer auth.loginMutex.RUnlock()

	if auth.config.LoginMaxRetries <= 0 || auth.config.LoginTimeout <= 0 {
		return false, 0
	}

	attempt, exists := auth.loginAttempts[identifier]
	if !exists {
		return false, 0
	}

	if attempt.LockedUntil.After(time.Now()) {
		remaining := int(time.Until(attempt.LockedUntil).Seconds())
		return true, remaining
	}

	return false, 0
}

func (auth *AuthService) RecordLoginAttempt(identifier string, success bool) {
	if auth.config.LoginMaxRetries <= 0 || auth.config.LoginTimeout <= 0 {
		return
	}

	auth.loginMutex.Lock()
	defer auth.loginMutex.Unlock()

	attempt, exists := auth.loginAttempts[identifier]
	if !exists {
		attempt = &LoginAttempt{}
		auth.loginAttempts[identifier] = attempt
	}

	attempt.LastAttempt = time.Now()

	if success {
		attempt.FailedAttempts = 0
		attempt.LockedUntil = time.Time{} // Reset lock time
		return
	}

	attempt.FailedAttempts++

	if attempt.FailedAttempts >= auth.config.LoginMaxRetries {
		attempt.LockedUntil = time.Now().Add(time.Duration(auth.config.LoginTimeout) * time.Second)
		tlog.App.Warn().Str("identifier", identifier).Int("timeout", auth.config.LoginTimeout).Msg("Account locked due to too many failed login attempts")
	}
}

func (auth *AuthService) IsEmailWhitelisted(email string) bool {
	return utils.CheckFilter(strings.Join(auth.config.OauthWhitelist, ","), email)
}

func (auth *AuthService) CreateSessionCookie(c *gin.Context, data *repository.Session) error {
	uuid, err := uuid.NewRandom()

	if err != nil {
		return err
	}

	var expiry int

	if data.TotpPending {
		expiry = 3600
	} else {
		expiry = auth.config.SessionExpiry
	}

	session := repository.CreateSessionParams{
		UUID:        uuid.String(),
		Username:    data.Username,
		Email:       data.Email,
		Name:        data.Name,
		Provider:    data.Provider,
		TotpPending: data.TotpPending,
		OAuthGroups: data.OAuthGroups,
		Expiry:      time.Now().Add(time.Duration(expiry) * time.Second).Unix(),
		CreatedAt:   time.Now().Unix(),
		OAuthName:   data.OAuthName,
		OAuthSub:    data.OAuthSub,
	}

	_, err = auth.queries.CreateSession(c, session)

	if err != nil {
		return err
	}

	c.SetCookie(auth.config.SessionCookieName, session.UUID, expiry, "/", fmt.Sprintf(".%s", auth.config.CookieDomain), auth.config.SecureCookie, true)

	return nil
}

func (auth *AuthService) RefreshSessionCookie(c *gin.Context) error {
	cookie, err := c.Cookie(auth.config.SessionCookieName)

	if err != nil {
		return err
	}

	session, err := auth.queries.GetSession(c, cookie)

	if err != nil {
		return err
	}

	currentTime := time.Now().Unix()

	var refreshThreshold int64

	if auth.config.SessionExpiry <= int(time.Hour.Seconds()) {
		refreshThreshold = int64(auth.config.SessionExpiry / 2)
	} else {
		refreshThreshold = int64(time.Hour.Seconds())
	}

	if session.Expiry-currentTime > refreshThreshold {
		return nil
	}

	newExpiry := session.Expiry + refreshThreshold

	_, err = auth.queries.UpdateSession(c, repository.UpdateSessionParams{
		Username:    session.Username,
		Email:       session.Email,
		Name:        session.Name,
		Provider:    session.Provider,
		TotpPending: session.TotpPending,
		OAuthGroups: session.OAuthGroups,
		Expiry:      newExpiry,
		OAuthName:   session.OAuthName,
		OAuthSub:    session.OAuthSub,
		UUID:        session.UUID,
	})

	if err != nil {
		return err
	}

	c.SetCookie(auth.config.SessionCookieName, cookie, int(newExpiry-currentTime), "/", fmt.Sprintf(".%s", auth.config.CookieDomain), auth.config.SecureCookie, true)
	tlog.App.Trace().Str("username", session.Username).Msg("Session cookie refreshed")

	return nil
}

func (auth *AuthService) DeleteSessionCookie(c *gin.Context) error {
	cookie, err := c.Cookie(auth.config.SessionCookieName)

	if err != nil {
		return err
	}

	err = auth.queries.DeleteSession(c, cookie)

	if err != nil {
		return err
	}

	c.SetCookie(auth.config.SessionCookieName, "", -1, "/", fmt.Sprintf(".%s", auth.config.CookieDomain), auth.config.SecureCookie, true)

	return nil
}

func (auth *AuthService) GetSessionCookie(c *gin.Context) (repository.Session, error) {
	cookie, err := c.Cookie(auth.config.SessionCookieName)

	if err != nil {
		return repository.Session{}, err
	}

	session, err := auth.queries.GetSession(c, cookie)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return repository.Session{}, fmt.Errorf("session not found")
		}
		return repository.Session{}, err
	}

	currentTime := time.Now().Unix()

	if auth.config.SessionMaxLifetime != 0 && session.CreatedAt != 0 {
		if currentTime-session.CreatedAt > int64(auth.config.SessionMaxLifetime) {
			err = auth.queries.DeleteSession(c, cookie)
			if err != nil {
				tlog.App.Error().Err(err).Msg("Failed to delete session exceeding max lifetime")
			}
			return repository.Session{}, fmt.Errorf("session expired due to max lifetime exceeded")
		}
	}

	if currentTime > session.Expiry {
		err = auth.queries.DeleteSession(c, cookie)
		if err != nil {
			tlog.App.Error().Err(err).Msg("Failed to delete expired session")
		}
		return repository.Session{}, fmt.Errorf("session expired")
	}

	return repository.Session{
		UUID:        session.UUID,
		Username:    session.Username,
		Email:       session.Email,
		Name:        session.Name,
		Provider:    session.Provider,
		TotpPending: session.TotpPending,
		OAuthGroups: session.OAuthGroups,
		OAuthName:   session.OAuthName,
		OAuthSub:    session.OAuthSub,
	}, nil
}

func (auth *AuthService) LocalAuthConfigured() bool {
	return len(auth.config.Users) > 0
}

func (auth *AuthService) LdapAuthConfigured() bool {
	return auth.ldap != nil
}

func (auth *AuthService) IsUserAllowed(c *gin.Context, context config.UserContext, acls config.App) bool {
	if context.OAuth {
		tlog.App.Debug().Msg("Checking OAuth whitelist")
		return utils.CheckFilter(acls.OAuth.Whitelist, context.Email)
	}

	if acls.Users.Block != "" {
		tlog.App.Debug().Msg("Checking blocked users")
		if utils.CheckFilter(acls.Users.Block, context.Username) {
			return false
		}
	}

	tlog.App.Debug().Msg("Checking users")
	return utils.CheckFilter(acls.Users.Allow, context.Username)
}

func (auth *AuthService) IsInOAuthGroup(c *gin.Context, context config.UserContext, requiredGroups string) bool {
	if requiredGroups == "" {
		return true
	}

	for id := range config.OverrideProviders {
		if context.Provider == id {
			tlog.App.Info().Str("provider", id).Msg("OAuth groups not supported for this provider")
			return true
		}
	}

	for userGroup := range strings.SplitSeq(context.OAuthGroups, ",") {
		if utils.CheckFilter(requiredGroups, strings.TrimSpace(userGroup)) {
			tlog.App.Trace().Str("group", userGroup).Str("required", requiredGroups).Msg("User group matched")
			return true
		}
	}

	tlog.App.Debug().Msg("No groups matched")
	return false
}

func (auth *AuthService) IsInLdapGroup(c *gin.Context, context config.UserContext, requiredGroups string) bool {
	if requiredGroups == "" {
		return true
	}

	for userGroup := range strings.SplitSeq(context.LdapGroups, ",") {
		if utils.CheckFilter(requiredGroups, strings.TrimSpace(userGroup)) {
			tlog.App.Trace().Str("group", userGroup).Str("required", requiredGroups).Msg("User group matched")
			return true
		}
	}

	tlog.App.Debug().Msg("No groups matched")
	return false
}

func (auth *AuthService) IsAuthEnabled(uri string, path config.AppPath) (bool, error) {
	// Check for block list
	if path.Block != "" {
		regex, err := regexp.Compile(path.Block)

		if err != nil {
			return true, err
		}

		if !regex.MatchString(uri) {
			return false, nil
		}
	}

	// Check for allow list
	if path.Allow != "" {
		regex, err := regexp.Compile(path.Allow)

		if err != nil {
			return true, err
		}

		if regex.MatchString(uri) {
			return false, nil
		}
	}

	return true, nil
}

func (auth *AuthService) GetBasicAuth(c *gin.Context) *config.User {
	username, password, ok := c.Request.BasicAuth()
	if !ok {
		tlog.App.Debug().Msg("No basic auth provided")
		return nil
	}
	return &config.User{
		Username: username,
		Password: password,
	}
}

func (auth *AuthService) CheckIP(acls config.AppIP, ip string) bool {
	// Merge the global and app IP filter
	blockedIps := append(auth.config.IP.Block, acls.Block...)
	allowedIPs := append(auth.config.IP.Allow, acls.Allow...)

	for _, blocked := range blockedIps {
		res, err := utils.FilterIP(blocked, ip)
		if err != nil {
			tlog.App.Warn().Err(err).Str("item", blocked).Msg("Invalid IP/CIDR in block list")
			continue
		}
		if res {
			tlog.App.Debug().Str("ip", ip).Str("item", blocked).Msg("IP is in blocked list, denying access")
			return false
		}
	}

	for _, allowed := range allowedIPs {
		res, err := utils.FilterIP(allowed, ip)
		if err != nil {
			tlog.App.Warn().Err(err).Str("item", allowed).Msg("Invalid IP/CIDR in allow list")
			continue
		}
		if res {
			tlog.App.Debug().Str("ip", ip).Str("item", allowed).Msg("IP is in allowed list, allowing access")
			return true
		}
	}

	if len(allowedIPs) > 0 {
		tlog.App.Debug().Str("ip", ip).Msg("IP not in allow list, denying access")
		return false
	}

	tlog.App.Debug().Str("ip", ip).Msg("IP not in allow or block list, allowing by default")
	return true
}

func (auth *AuthService) IsBypassedIP(acls config.AppIP, ip string) bool {
	for _, bypassed := range acls.Bypass {
		res, err := utils.FilterIP(bypassed, ip)
		if err != nil {
			tlog.App.Warn().Err(err).Str("item", bypassed).Msg("Invalid IP/CIDR in bypass list")
			continue
		}
		if res {
			tlog.App.Debug().Str("ip", ip).Str("item", bypassed).Msg("IP is in bypass list, allowing access")
			return true
		}
	}

	tlog.App.Debug().Str("ip", ip).Msg("IP not in bypass list, continuing with authentication")
	return false
}
