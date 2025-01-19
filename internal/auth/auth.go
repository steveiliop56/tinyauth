package auth

import (
	"tinyauth/internal/types"

	"golang.org/x/crypto/bcrypt"
)

func FindUser(userList types.UserList, username string) (*types.User) {
	for _, user := range userList.Users {
		if user.Username == username {
			return &user
		}
	}
	return nil
}

func CheckPassword(user types.User, password string) bool {
	hashedPasswordErr := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	return hashedPasswordErr == nil
}