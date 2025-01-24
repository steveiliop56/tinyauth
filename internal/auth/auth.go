package auth

import (
	"tinyauth/internal/types"

	"golang.org/x/crypto/bcrypt"
)

func NewAuth(userList types.Users, whitelist []string) *Auth {
	return &Auth{
		Users:     userList,
		Whitelist: whitelist,
	}
}

type Auth struct {
	Users     types.Users
	Whitelist []string
}

func (auth *Auth) GetUser(email string) *types.User {
	for _, user := range auth.Users {
		if user.Email == email {
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
	if len(auth.Whitelist) == 0 {
		return true
	}
	for _, email := range auth.Whitelist {
		if email == emailSrc {
			return true
		}
	}
	return false
}
