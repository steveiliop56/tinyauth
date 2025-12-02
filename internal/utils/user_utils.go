package utils

import (
	"errors"
	"strings"
	"tinyauth/internal/config"
)

func ParseUsers(users string) ([]config.User, error) {
	var usersParsed []config.User

	users = strings.TrimSpace(users)

	if users == "" {
		return []config.User{}, nil
	}

	userList := strings.Split(users, ",")

	if len(userList) == 0 {
		return []config.User{}, errors.New("invalid user format")
	}

	for _, user := range userList {
		if strings.TrimSpace(user) == "" {
			continue
		}
		parsed, err := ParseUser(strings.TrimSpace(user))
		if err != nil {
			return []config.User{}, err
		}
		usersParsed = append(usersParsed, parsed)
	}

	return usersParsed, nil
}

func GetUsers(conf string, file string) ([]config.User, error) {
	var users string

	if conf == "" && file == "" {
		return []config.User{}, nil
	}

	if conf != "" {
		users += conf
	}

	if file != "" {
		contents, err := ReadFile(file)
		if err != nil {
			return []config.User{}, err
		}
		if users != "" {
			users += ","
		}
		users += ParseFileToLine(contents)
	}

	return ParseUsers(users)
}

func ParseUser(user string) (config.User, error) {
	if strings.Contains(user, "$$") {
		user = strings.ReplaceAll(user, "$$", "$")
	}

	userSplit := strings.Split(user, ":")

	if len(userSplit) < 2 || len(userSplit) > 3 {
		return config.User{}, errors.New("invalid user format")
	}

	for _, userPart := range userSplit {
		if strings.TrimSpace(userPart) == "" {
			return config.User{}, errors.New("invalid user format")
		}
	}

	if len(userSplit) == 2 {
		return config.User{
			Username: strings.TrimSpace(userSplit[0]),
			Password: strings.TrimSpace(userSplit[1]),
		}, nil
	}

	return config.User{
		Username:   strings.TrimSpace(userSplit[0]),
		Password:   strings.TrimSpace(userSplit[1]),
		TotpSecret: strings.TrimSpace(userSplit[2]),
	}, nil
}
