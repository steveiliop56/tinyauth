package utils

import (
	"errors"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"tinyauth/internal/constants"
	"tinyauth/internal/types"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// Parses a list of comma separated users in a struct
func ParseUsers(users string) (types.Users, error) {
	log.Debug().Msg("Parsing users")

	// Create a new users struct
	var usersParsed types.Users

	// Split the users by comma
	userList := strings.Split(users, ",")

	// Check if there are any users
	if len(userList) == 0 {
		return types.Users{}, errors.New("invalid user format")
	}

	// Loop through the users and split them by colon
	for _, user := range userList {
		parsed, err := ParseUser(user)

		// Check if there was an error
		if err != nil {
			return types.Users{}, err
		}

		// Append the user to the users struct
		usersParsed = append(usersParsed, parsed)
	}

	log.Debug().Msg("Parsed users")

	// Return the users struct
	return usersParsed, nil
}

// Get upper domain parses a hostname and returns the upper domain (e.g. sub1.sub2.domain.com -> sub2.domain.com)
func GetUpperDomain(urlSrc string) (string, error) {
	// Make sure the url is valid
	urlParsed, err := url.Parse(urlSrc)

	// Check if there was an error
	if err != nil {
		return "", err
	}

	// Split the hostname by period
	urlSplitted := strings.Split(urlParsed.Hostname(), ".")

	// Get the last part of the url
	urlFinal := strings.Join(urlSplitted[1:], ".")

	// Return the root domain
	return urlFinal, nil
}

// Reads a file and returns the contents
func ReadFile(file string) (string, error) {
	// Check if the file exists
	_, err := os.Stat(file)

	// Check if there was an error
	if err != nil {
		return "", err
	}

	// Read the file
	data, err := os.ReadFile(file)

	// Check if there was an error
	if err != nil {
		return "", err
	}

	// Return the file contents
	return string(data), nil
}

// Parses a file into a comma separated list of users
func ParseFileToLine(content string) string {
	// Split the content by newline
	lines := strings.Split(content, "\n")

	// Create a list of users
	users := make([]string, 0)

	// Loop through the lines, trimming the whitespace and appending to the users list
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		users = append(users, strings.TrimSpace(line))
	}

	// Return the users as a comma separated string
	return strings.Join(users, ",")
}

// Get the secret from the config or file
func GetSecret(conf string, file string) string {
	// If neither the config or file is set, return an empty string
	if conf == "" && file == "" {
		return ""
	}

	// If the config is set, return the config (environment variable)
	if conf != "" {
		return conf
	}

	// If the file is set, read the file
	contents, err := ReadFile(file)

	// Check if there was an error
	if err != nil {
		return ""
	}

	// Return the contents of the file
	return ParseSecretFile(contents)
}

// Get the users from the config or file
func GetUsers(conf string, file string) (types.Users, error) {
	// Create a string to store the users
	var users string

	// If neither the config or file is set, return an empty users struct
	if conf == "" && file == "" {
		return types.Users{}, nil
	}

	// If the config (environment) is set, append the users to the users string
	if conf != "" {
		log.Debug().Msg("Using users from config")
		users += conf
	}

	// If the file is set, read the file and append the users to the users string
	if file != "" {
		// Read the file
		contents, err := ReadFile(file)

		// If there isn't an error we can append the users to the users string
		if err == nil {
			log.Debug().Msg("Using users from file")

			// Append the users to the users string
			if users != "" {
				users += ","
			}

			// Parse the file contents into a comma separated list of users
			users += ParseFileToLine(contents)
		}
	}

	// Return the parsed users
	return ParseUsers(users)
}

// Parse the docker labels to the tinyauth labels struct
func GetTinyauthLabels(labels map[string]string) types.TinyauthLabels {
	// Create a new tinyauth labels struct
	var tinyauthLabels types.TinyauthLabels

	// Loop through the labels
	for label, value := range labels {

		// Check if the label is in the tinyauth labels
		if slices.Contains(constants.TinyauthLabels, label) {

			log.Debug().Str("label", label).Msg("Found label")

			// Add the label value to the tinyauth labels struct
			switch label {
			case "tinyauth.oauth.whitelist":
				tinyauthLabels.OAuthWhitelist = value
			case "tinyauth.users":
				tinyauthLabels.Users = value
			case "tinyauth.allowed":
				tinyauthLabels.Allowed = value
			case "tinyauth.headers":
				tinyauthLabels.Headers = make(map[string]string)
				headers := strings.Split(value, ",")
				for _, header := range headers {
					headerSplit := strings.Split(header, "=")
					if len(headerSplit) != 2 {
						continue
					}
					tinyauthLabels.Headers[headerSplit[0]] = headerSplit[1]
				}
			case "tinyauth.oauth.groups":
				tinyauthLabels.OAuthGroups = value
			}
		}
	}

	// Return the tinyauth labels
	return tinyauthLabels
}

// Check if any of the OAuth providers are configured based on the client id and secret
func OAuthConfigured(config types.Config) bool {
	return (config.GithubClientId != "" && config.GithubClientSecret != "") || (config.GoogleClientId != "" && config.GoogleClientSecret != "") || (config.GenericClientId != "" && config.GenericClientSecret != "")
}

// Filter helper function
func Filter[T any](slice []T, test func(T) bool) (res []T) {
	for _, value := range slice {
		if test(value) {
			res = append(res, value)
		}
	}
	return res
}

// Parse user
func ParseUser(user string) (types.User, error) {
	// Check if the user is escaped
	if strings.Contains(user, "$$") {
		user = strings.ReplaceAll(user, "$$", "$")
	}

	// Split the user by colon
	userSplit := strings.Split(user, ":")

	// Check if the user is in the correct format
	if len(userSplit) < 2 || len(userSplit) > 3 {
		return types.User{}, errors.New("invalid user format")
	}

	// Check for empty strings
	for _, userPart := range userSplit {
		if strings.TrimSpace(userPart) == "" {
			return types.User{}, errors.New("invalid user format")
		}
	}

	// Check if the user has a totp secret
	if len(userSplit) == 2 {
		return types.User{
			Username: strings.TrimSpace(userSplit[0]),
			Password: strings.TrimSpace(userSplit[1]),
		}, nil
	}

	// Return the user struct
	return types.User{
		Username:   strings.TrimSpace(userSplit[0]),
		Password:   strings.TrimSpace(userSplit[1]),
		TotpSecret: strings.TrimSpace(userSplit[2]),
	}, nil
}

// Parse secret file
func ParseSecretFile(contents string) string {
	// Split to lines
	lines := strings.Split(contents, "\n")

	// Loop through the lines
	for _, line := range lines {
		// Check if the line is empty
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Return the line
		return strings.TrimSpace(line)
	}

	// Return an empty string
	return ""
}

// Check if a string matches a regex or a whitelist
func CheckWhitelist(whitelist string, str string) bool {
	// Check if the whitelist is empty
	if len(strings.TrimSpace(whitelist)) == 0 {
		return true
	}

	// Check if the whitelist is a regex
	if strings.HasPrefix(whitelist, "/") && strings.HasSuffix(whitelist, "/") {
		// Create regex
		re, err := regexp.Compile(whitelist[1 : len(whitelist)-1])

		// Check if there was an error
		if err != nil {
			log.Error().Err(err).Msg("Error compiling regex")
			return false
		}

		// Check if the string matches the regex
		if re.MatchString(str) {
			return true
		}
	}

	// Split the whitelist by comma
	whitelistSplit := strings.Split(whitelist, ",")

	// Loop through the whitelist
	for _, item := range whitelistSplit {
		// Check if the item matches with the string
		if strings.TrimSpace(item) == str {
			return true
		}
	}

	// Return false if no match was found
	return false
}

// Capitalize just the first letter of a string
func Capitalize(str string) string {
	if len(str) == 0 {
		return ""
	}
	return strings.ToUpper(string([]rune(str)[0])) + string([]rune(str)[1:])
}

// Sanitize header removes all control characters from a string
func SanitizeHeader(header string) string {
	return strings.Map(func(r rune) rune {
		// Allow only printable ASCII characters (32-126) and safe whitespace (space, tab)
		if r == ' ' || r == '\t' || (r >= 32 && r <= 126) {
			return r
		}
		return -1
	}, header)
}

// Generate a static identifier from a string
func GenerateIdentifier(str string) string {
	// Create a new UUID
	uuid := uuid.NewSHA1(uuid.NameSpaceURL, []byte(str))

	// Convert the UUID to a string
	uuidString := uuid.String()

	// Show the UUID
	log.Debug().Str("uuid", uuidString).Msg("Generated UUID")

	// Convert the UUID to a string
	return strings.Split(uuidString, "-")[0]
}
