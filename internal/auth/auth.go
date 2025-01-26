package auth

import (
	"tinyauth/internal/types"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

func NewAuth(userList types.Users, oauthWhitelist []string) *Auth {
	return &Auth{
		Users:          userList,
		OAuthWhitelist: oauthWhitelist,
	}
}

type Auth struct {
	Users          types.Users
	OAuthWhitelist []string
}

func (auth *Auth) GetUser(username string) *types.User {
	for _, user := range auth.Users {
		if user.Username == username {
			return &user
		}
	}
	return nil
}

func (auth *Auth) CheckPassword(user types.User, password string) bool {
	hashedPasswordErr := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	return hashedPasswordErr == nil
}

func (auth *Auth) EmailWhitelisted(emailSrc string) bool {
	if len(auth.OAuthWhitelist) == 0 {
		return true
	}
	for _, email := range auth.OAuthWhitelist {
		if email == emailSrc {
			return true
		}
	}
	return false
}

func (auth *Auth) CreateSessionCookie(c *gin.Context, data *types.SessionCookie) {
	sessions := sessions.Default(c)
	sessions.Set("username", data.Username)
	sessions.Set("provider", data.Provider)
	sessions.Save()
}

func (auth *Auth) DeleteSessionCookie(c *gin.Context) {
	sessions := sessions.Default(c)
	sessions.Clear()
	sessions.Save()
}

func (auth *Auth) GetSessionCookie(c *gin.Context) (types.SessionCookie, error) {
	sessions := sessions.Default(c)

	cookieUsername := sessions.Get("username")
	cookieProvider := sessions.Get("provider")

	username, usernameOk := cookieUsername.(string)
	provider, providerOk := cookieProvider.(string)

	if !usernameOk || !providerOk {
		log.Warn().Msg("Session cookie invalid")
		return types.SessionCookie{}, nil
	}

	return types.SessionCookie{
		Username: username,
		Provider: provider,
	}, nil
}
