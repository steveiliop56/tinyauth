package utils

import (
	"errors"
	"strings"
	"tinyauth/internal/types"
)

func CreateUsersList(users string) (types.UserList, error) {
	var userList types.UserList
	userListString := strings.Split(users, ",")

	if len(userListString) == 0 {
		return types.UserList{}, errors.New("no users found")
	}

	for _, user := range userListString {
		userSplit := strings.Split(user, ":")
		if len(userSplit) != 2 {
			return types.UserList{}, errors.New("invalid user format")
		}
		userList.Users = append(userList.Users, types.User{
			Username: userSplit[0],
			Password: userSplit[1],
		})
	}

	return userList, nil
}