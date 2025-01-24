package auth

import (
	"tinyauth/internal/types"

	"golang.org/x/crypto/bcrypt"
)

func NewAuth(userList types.Users) *Auth {
	return &Auth{
		Users: userList,
	}
}

type Auth struct {
	Users types.Users
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