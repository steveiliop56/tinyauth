package utils

import (
	"errors"
	"net/url"
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

func GetRootURL(urlSrc string) (string, error) {
	urlParsed, parseErr := url.Parse(urlSrc)

	if parseErr != nil {
		return "", parseErr
	}

	urlSplitted := strings.Split(urlParsed.Host, ".")

	urlFinal := urlSplitted[len(urlSplitted)-2] + "." + urlSplitted[len(urlSplitted)-1]

	return urlFinal, nil
}