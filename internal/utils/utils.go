package utils

import (
	"errors"
	"net/url"
	"os"
	"strings"
	"tinyauth/internal/types"

	"github.com/rs/zerolog/log"
)

func ParseUsers(users string) (types.Users, error) {
	log.Debug().Msg("Parsing users")
	var usersParsed types.Users
	userList := strings.Split(users, ",")

	log.Debug().Strs("users", userList).Msg("Splitted users")

	if len(userList) == 0 {
		return types.Users{}, errors.New("invalid user format")
	}

	for _, user := range userList {
		userSplit := strings.Split(user, ":")
		log.Debug().Strs("user", userSplit).Msg("Splitting user")
		if len(userSplit) != 2 {
			return types.Users{}, errors.New("invalid user format")
		}
		usersParsed = append(usersParsed, types.User{
			Username: userSplit[0],
			Password: userSplit[1],
		})
	}

	log.Debug().Interface("users", usersParsed).Msg("Parsed users")

	return usersParsed, nil
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

func ReadFile(file string) (string, error) {
	_, statErr := os.Stat(file)

	if statErr != nil {
		return "", statErr
	}

	data, readErr := os.ReadFile(file)

	if readErr != nil {
		return "", readErr
	}

	return string(data), nil
}

func ParseFileToLine(content string) string {
	lines := strings.Split(content, "\n")
	users := make([]string, 0)

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		users = append(users, line)
	}

	return strings.Join(users, ",")
}

func GetSecret(env string, file string) string {
	if env == "" && file == "" {
		log.Debug().Msg("No secret provided")
		return ""
	}

	if env != "" {
		log.Debug().Str("secret", env).Msg("Using secret from env")
		return env
	}

	contents, err := ReadFile(file)

	if err != nil {
		return ""
	}

	log.Debug().Str("secret", contents).Msg("Using secret from file")

	return contents
}

func GetUsers(env string, file string) (types.Users, error) {
	var users string

	if env == "" && file == "" {
		return types.Users{}, errors.New("no users provided")
	}

	if env != "" {
		log.Debug().Str("users", env).Msg("Using users from env")
		users += env
	}

	if file != "" {
		fileContents, fileErr := ReadFile(file)

		if fileErr == nil {
			log.Debug().Str("users", ParseFileToLine(fileContents)).Msg("Using users from file")
			users += ","
			users += ParseFileToLine(fileContents)
		}
	}

	return ParseUsers(users)
}
