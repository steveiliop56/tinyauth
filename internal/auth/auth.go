package auth

import (
	"tinyauth/internal/types"

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
	hashedPasswordErr := bcrypt.CompareHashAndPassword([]byte(user.Username), []byte(password))
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
