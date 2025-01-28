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

	if len(userList) == 0 {
		return types.Users{}, errors.New("invalid user format")
	}

	for _, user := range userList {
		userSplit := strings.Split(user, ":")
		if len(userSplit) != 2 {
			return types.Users{}, errors.New("invalid user format")
		}
		usersParsed = append(usersParsed, types.User{
			Username: userSplit[0],
			Password: userSplit[1],
		})
	}

	log.Debug().Msg("Parsed users")

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

		users = append(users, strings.TrimSpace(line))
	}

	return strings.Join(users, ",")
}

func GetSecret(conf string, file string) string {
	if conf == "" && file == "" {
		return ""
	}

	if conf != "" {
		return conf
	}

	contents, err := ReadFile(file)

	if err != nil {
		return ""
	}

	return contents
}

func GetUsers(conf string, file string) (types.Users, error) {
	var users string

	if conf == "" && file == "" {
		return types.Users{}, errors.New("no users provided")
	}

	if conf != "" {
		log.Debug().Msg("Using users from config")
		users += conf
	}

	if file != "" {
		fileContents, fileErr := ReadFile(file)

		if fileErr == nil {
			log.Debug().Msg("Using users from file")
			if users != "" {
				users += ","
			}
			users += ParseFileToLine(fileContents)
		}
	}

	return ParseUsers(users)
}

func OAuthConfigured(config types.Config) bool {
	return (config.GithubClientId != "" && config.GithubClientSecret != "") || (config.GoogleClientId != "" && config.GoogleClientSecret != "") || (config.GenericClientId != "" && config.GenericClientSecret != "")
}
