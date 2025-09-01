package service

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"tinyauth/internal/config"
	"tinyauth/internal/model"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type LoginAttempt struct {
	FailedAttempts int
	LastAttempt    time.Time
	LockedUntil    time.Time
}

type AuthServiceConfig struct {
	Users             []config.User
	OauthWhitelist    string
	SessionExpiry     int
	SecureCookie      bool
	RootDomain        string
	LoginTimeout      int
	LoginMaxRetries   int
	SessionCookieName string
}

type AuthService struct {
	config        AuthServiceConfig
	docker        *DockerService
	loginAttempts map[string]*LoginAttempt
	loginMutex    sync.RWMutex
	ldap          *LdapService
	database      *gorm.DB
}

func NewAuthService(config AuthServiceConfig, docker *DockerService, ldap *LdapService, database *gorm.DB) *AuthService {
	return &AuthService{
		config:        config,
		docker:        docker,
		loginAttempts: make(map[string]*LoginAttempt),
		ldap:          ldap,
		database:      database,
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
		userDN, err := auth.ldap.Search(username)

		if err != nil {
			log.Warn().Err(err).Str("username", username).Msg("Failed to search for user in LDAP")
			return config.UserSearch{
				Type: "error",
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
				log.Warn().Err(err).Str("username", search.Username).Msg("Failed to bind to LDAP")
				return false
			}

			err = auth.ldap.Bind(auth.ldap.Config.BindDN, auth.ldap.Config.BindPassword)
			if err != nil {
				log.Error().Err(err).Msg("Failed to rebind with service account after user authentication")
				return false
			}

			return true
		}
	default:
		log.Debug().Str("type", search.Type).Msg("Unknown user type for authentication")
		return false
	}

	log.Warn().Str("username", search.Username).Msg("User authentication failed")
	return false
}

func (auth *AuthService) GetLocalUser(username string) config.User {
	for _, user := range auth.config.Users {
		if user.Username == username {
			return user
		}
	}

	log.Warn().Str("username", username).Msg("Local user not found")
	return config.User{}
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
		log.Warn().Str("identifier", identifier).Int("timeout", auth.config.LoginTimeout).Msg("Account locked due to too many failed login attempts")
	}
}

func (auth *AuthService) IsEmailWhitelisted(email string) bool {
	return utils.CheckFilter(auth.config.OauthWhitelist, email)
}

func (auth *AuthService) CreateSessionCookie(c *gin.Context, data *config.SessionCookie) error {
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

	session := model.Session{
		UUID:        uuid.String(),
		Username:    data.Username,
		Email:       data.Email,
		Name:        data.Name,
		Provider:    data.Provider,
		TOTPPending: data.TotpPending,
		OAuthGroups: data.OAuthGroups,
		Expiry:      time.Now().Add(time.Duration(expiry) * time.Second).Unix(),
	}

	err = auth.database.Create(&session).Error

	if err != nil {
		return err
	}

	c.SetCookie(auth.config.SessionCookieName, session.UUID, expiry, "/", fmt.Sprintf(".%s", auth.config.RootDomain), auth.config.SecureCookie, true)

	return nil
}

func (auth *AuthService) DeleteSessionCookie(c *gin.Context) error {
	cookie, err := c.Cookie(auth.config.SessionCookieName)

	if err != nil {
		return err
	}

	res := auth.database.Unscoped().Where("uuid = ?", cookie).Delete(&model.Session{})

	if res.Error != nil {
		return res.Error
	}

	c.SetCookie(auth.config.SessionCookieName, "", -1, "/", fmt.Sprintf(".%s", auth.config.RootDomain), auth.config.SecureCookie, true)

	return nil
}

func (auth *AuthService) GetSessionCookie(c *gin.Context) (config.SessionCookie, error) {
	cookie, err := c.Cookie(auth.config.SessionCookieName)

	if err != nil {
		return config.SessionCookie{}, err
	}

	var session model.Session

	res := auth.database.Unscoped().Where("uuid = ?", cookie).First(&session)

	if res.Error != nil {
		return config.SessionCookie{}, res.Error
	}

	if res.RowsAffected == 0 {
		return config.SessionCookie{}, fmt.Errorf("session not found")
	}

	currentTime := time.Now().Unix()

	if currentTime > session.Expiry {
		res := auth.database.Unscoped().Where("uuid = ?", session.UUID).Delete(&model.Session{})
		if res.Error != nil {
			log.Error().Err(res.Error).Msg("Failed to delete expired session")
		}
		return config.SessionCookie{}, fmt.Errorf("session expired")
	}

	return config.SessionCookie{
		UUID:        session.UUID,
		Username:    session.Username,
		Email:       session.Email,
		Name:        session.Name,
		Provider:    session.Provider,
		TotpPending: session.TOTPPending,
		OAuthGroups: session.OAuthGroups,
	}, nil
}

func (auth *AuthService) UserAuthConfigured() bool {
	return len(auth.config.Users) > 0 || auth.ldap != nil
}

func (auth *AuthService) IsResourceAllowed(c *gin.Context, context config.UserContext, labels config.AppLabels) bool {
	if context.OAuth {
		log.Debug().Msg("Checking OAuth whitelist")
		return utils.CheckFilter(labels.OAuth.Whitelist, context.Email)
	}

	if labels.Users.Block != "" {
		log.Debug().Msg("Checking blocked users")
		if utils.CheckFilter(labels.Users.Block, context.Username) {
			return false
		}
	}

	log.Debug().Msg("Checking users")
	return utils.CheckFilter(labels.Users.Allow, context.Username)
}

func (auth *AuthService) IsInOAuthGroup(c *gin.Context, context config.UserContext, requiredGroups string) bool {
	if requiredGroups == "" {
		return true
	}

	if context.Provider != "generic" {
		log.Debug().Msg("Not using generic provider, skipping group check")
		return true
	}

	for _, userGroup := range strings.Split(context.OAuthGroups, ",") {
		if utils.CheckFilter(requiredGroups, strings.TrimSpace(userGroup)) {
			return true
		}
	}

	log.Debug().Msg("No groups matched")
	return false
}

func (auth *AuthService) IsAuthEnabled(uri string, path config.PathLabels) (bool, error) {
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
		log.Debug().Msg("No basic auth provided")
		return nil
	}
	return &config.User{
		Username: username,
		Password: password,
	}
}

func (auth *AuthService) CheckIP(labels config.IPLabels, ip string) bool {
	for _, blocked := range labels.Block {
		res, err := utils.FilterIP(blocked, ip)
		if err != nil {
			log.Warn().Err(err).Str("item", blocked).Msg("Invalid IP/CIDR in block list")
			continue
		}
		if res {
			log.Debug().Str("ip", ip).Str("item", blocked).Msg("IP is in blocked list, denying access")
			return false
		}
	}

	for _, allowed := range labels.Allow {
		res, err := utils.FilterIP(allowed, ip)
		if err != nil {
			log.Warn().Err(err).Str("item", allowed).Msg("Invalid IP/CIDR in allow list")
			continue
		}
		if res {
			log.Debug().Str("ip", ip).Str("item", allowed).Msg("IP is in allowed list, allowing access")
			return true
		}
	}

	if len(labels.Allow) > 0 {
		log.Debug().Str("ip", ip).Msg("IP not in allow list, denying access")
		return false
	}

	log.Debug().Str("ip", ip).Msg("IP not in allow or block list, allowing by default")
	return true
}

func (auth *AuthService) IsBypassedIP(labels config.IPLabels, ip string) bool {
	for _, bypassed := range labels.Bypass {
		res, err := utils.FilterIP(bypassed, ip)
		if err != nil {
			log.Warn().Err(err).Str("item", bypassed).Msg("Invalid IP/CIDR in bypass list")
			continue
		}
		if res {
			log.Debug().Str("ip", ip).Str("item", bypassed).Msg("IP is in bypass list, allowing access")
			return true
		}
	}

	log.Debug().Str("ip", ip).Msg("IP not in bypass list, continuing with authentication")
	return false
}
