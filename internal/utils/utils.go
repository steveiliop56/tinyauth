package utils

import (
	"errors"
	"net/url"
	"os"
	"strings"
	"tinyauth/internal/types"
)

func ParseUsers(users string) (types.UserList, error) {
	var userList types.UserList
	userListString := strings.Split(users, ",")

	if len(userListString) == 0 {
		return types.UserList{}, errors.New("invalid user format")
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

	urlFinal := strings.Join(urlSplitted[1:], ".")

	return urlFinal, nil
}

func GetUsersFromFile(usersFile string) (string, error) {
	_, statErr := os.Stat(usersFile)

	if statErr != nil {
		return "", statErr
	}

	data, readErr := os.ReadFile(usersFile)

	if readErr != nil {
		return "", readErr
	}

	return string(data), nil
}
