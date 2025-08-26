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
	Domain            string
	LoginTimeout      int
	LoginMaxRetries   int
	SessionCookieName string
}

type AuthService struct {
	Config        AuthServiceConfig
	Docker        *DockerService
	LoginAttempts map[string]*LoginAttempt
	LoginMutex    sync.RWMutex
	LDAP          *LdapService
	Database      *DatabaseService
}

func NewAuthService(config AuthServiceConfig, docker *DockerService, ldap *LdapService, database *DatabaseService) *AuthService {
	return &AuthService{
		Config:        config,
		Docker:        docker,
		LoginAttempts: make(map[string]*LoginAttempt),
		LDAP:          ldap,
		Database:      database,
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

	if auth.LDAP != nil {
		userDN, err := auth.LDAP.Search(username)

		if err != nil {
			log.Warn().Err(err).Str("username", username).Msg("Failed to search for user in LDAP")
			return config.UserSearch{}
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
		if auth.LDAP != nil {
			err := auth.LDAP.Bind(search.Username, password)
			if err != nil {
				log.Warn().Err(err).Str("username", search.Username).Msg("Failed to bind to LDAP")
				return false
			}

			err = auth.LDAP.Bind(auth.LDAP.Config.BindDN, auth.LDAP.Config.BindPassword)
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
	for _, user := range auth.Config.Users {
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
	auth.LoginMutex.RLock()
	defer auth.LoginMutex.RUnlock()

	if auth.Config.LoginMaxRetries <= 0 || auth.Config.LoginTimeout <= 0 {
		return false, 0
	}

	attempt, exists := auth.LoginAttempts[identifier]
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
	if auth.Config.LoginMaxRetries <= 0 || auth.Config.LoginTimeout <= 0 {
		return
	}

	auth.LoginMutex.Lock()
	defer auth.LoginMutex.Unlock()

	attempt, exists := auth.LoginAttempts[identifier]
	if !exists {
		attempt = &LoginAttempt{}
		auth.LoginAttempts[identifier] = attempt
	}

	attempt.LastAttempt = time.Now()

	if success {
		attempt.FailedAttempts = 0
		attempt.LockedUntil = time.Time{} // Reset lock time
		return
	}

	attempt.FailedAttempts++

	if attempt.FailedAttempts >= auth.Config.LoginMaxRetries {
		attempt.LockedUntil = time.Now().Add(time.Duration(auth.Config.LoginTimeout) * time.Second)
		log.Warn().Str("identifier", identifier).Int("timeout", auth.Config.LoginTimeout).Msg("Account locked due to too many failed login attempts")
	}
}

func (auth *AuthService) IsEmailWhitelisted(email string) bool {
	return utils.CheckFilter(auth.Config.OauthWhitelist, email)
}

func (auth *AuthService) CreateSessionCookie(c *gin.Context, data *config.SessionCookie) error {
	db := auth.Database.GetDatabase()
	uuid, err := uuid.NewRandom()

	if err != nil {
		return err
	}

	var expiry int

	if data.TotpPending {
		expiry = 3600
	} else {
		expiry = auth.Config.SessionExpiry
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

	err = db.Create(&session).Error

	if err != nil {
		return err
	}

	c.SetCookie(auth.Config.SessionCookieName, session.UUID, expiry, "/", fmt.Sprintf(".%s", auth.Config.Domain), auth.Config.SecureCookie, true)

	return nil
}

func (auth *AuthService) DeleteSessionCookie(c *gin.Context) error {
	db := auth.Database.GetDatabase()
	session, err := auth.GetSessionCookie(c)

	if err != nil {
		return err
	}

	res := db.Unscoped().Where("uuid = ?", session.UUID).Delete(&model.Session{})

	if res.Error != nil {
		return res.Error
	}

	c.SetCookie(auth.Config.SessionCookieName, "", -1, "/", fmt.Sprintf(".%s", auth.Config.Domain), auth.Config.SecureCookie, true)

	return nil
}

func (auth *AuthService) GetSessionCookie(c *gin.Context) (config.SessionCookie, error) {
	db := auth.Database.GetDatabase()
	cookie, err := c.Cookie(auth.Config.SessionCookieName)

	if err != nil {
		return config.SessionCookie{}, err
	}

	var session model.Session

	res := db.Unscoped().Where("uuid = ?", cookie).First(&session)

	if res.Error != nil {
		return config.SessionCookie{}, res.Error
	}

	if res.RowsAffected == 0 {
		return config.SessionCookie{}, fmt.Errorf("session not found")
	}

	currentTime := time.Now().Unix()

	if currentTime > session.Expiry {
		res := db.Unscoped().Where("uuid = ?", session.UUID).Delete(&model.Session{})
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
	return len(auth.Config.Users) > 0 || auth.LDAP != nil
}

func (auth *AuthService) IsResourceAllowed(c *gin.Context, context config.UserContext, labels config.Labels) bool {
	if context.OAuth {
		log.Debug().Msg("Checking OAuth whitelist")
		return utils.CheckFilter(labels.OAuth.Whitelist, context.Email)
	}

	log.Debug().Msg("Checking users")
	return utils.CheckFilter(labels.Users, context.Username)
}

func (auth *AuthService) IsInOAuthGroup(c *gin.Context, context config.UserContext, labels config.Labels) bool {
	if labels.OAuth.Groups == "" {
		return true
	}

	if context.Provider != "generic" {
		log.Debug().Msg("Not using generic provider, skipping group check")
		return true
	}

	// No need to parse since they are from the API response
	oauthGroups := strings.Split(context.OAuthGroups, ",")

	for _, group := range oauthGroups {
		if utils.CheckFilter(labels.OAuth.Groups, group) {
			return true
		}
	}

	log.Debug().Msg("No groups matched")
	return false
}

func (auth *AuthService) IsAuthEnabled(uri string, labels config.Labels) (bool, error) {
	if labels.Allowed == "" {
		return true, nil
	}

	regex, err := regexp.Compile(labels.Allowed)

	if err != nil {
		return true, err
	}

	if regex.MatchString(uri) {
		return false, nil
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

func (auth *AuthService) CheckIP(labels config.Labels, ip string) bool {
	for _, blocked := range labels.IP.Block {
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

	for _, allowed := range labels.IP.Allow {
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

	if len(labels.IP.Allow) > 0 {
		log.Debug().Str("ip", ip).Msg("IP not in allow list, denying access")
		return false
	}

	log.Debug().Str("ip", ip).Msg("IP not in allow or block list, allowing by default")
	return true
}

func (auth *AuthService) IsBypassedIP(labels config.Labels, ip string) bool {
	for _, bypassed := range labels.IP.Bypass {
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
