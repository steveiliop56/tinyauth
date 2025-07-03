package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"tinyauth/internal/types"

	"github.com/traefik/paerser/parser"
	"golang.org/x/crypto/hkdf"

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

// Parse the headers in a map[string]string format
func ParseHeaders(headers []string) map[string]string {
	// Create a map to store the headers
	headerMap := make(map[string]string)

	// Loop through the headers
	for _, header := range headers {
		split := strings.SplitN(header, "=", 2)
		if len(split) != 2 {
			log.Warn().Str("header", header).Msg("Invalid header format, skipping")
			continue
		}
		key := SanitizeHeader(strings.TrimSpace(split[0]))
		value := SanitizeHeader(strings.TrimSpace(split[1]))
		headerMap[key] = value
	}

	// Return the header map
	return headerMap
}

// Get labels parses a map of labels into a struct with only the needed labels
func GetLabels(labels map[string]string) (types.Labels, error) {
	// Create a new labels struct
	var labelsParsed types.Labels

	// Decode the labels into the labels struct
	err := parser.Decode(labels, &labelsParsed, "tinyauth", "tinyauth.users", "tinyauth.allowed", "tinyauth.headers", "tinyauth.domain", "tinyauth.basic", "tinyauth.oauth", "tinyauth.ip")

	// Check if there was an error
	if err != nil {
		log.Error().Err(err).Msg("Error parsing labels")
		return types.Labels{}, err
	}

	// Return the labels struct
	return labelsParsed, nil
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

// Get a basic auth header from a username and password
func GetBasicAuth(username string, password string) string {
	// Create the auth string
	auth := username + ":" + password

	// Encode the auth string to base64
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// Check if an IP is contained in a CIDR range/matches a single IP
func FilterIP(filter string, ip string) (bool, error) {
	// Convert the check IP to an IP instance
	ipAddr := net.ParseIP(ip)

	// Check if the filter is a CIDR range
	if strings.Contains(filter, "/") {
		// Parse the CIDR range
		_, cidr, err := net.ParseCIDR(filter)

		// Check if there was an error
		if err != nil {
			return false, err
		}

		// Check if the IP is in the CIDR range
		return cidr.Contains(ipAddr), nil
	}

	// Parse the filter as a single IP
	ipFilter := net.ParseIP(filter)

	// Check if the IP is valid
	if ipFilter == nil {
		return false, errors.New("invalid IP address in filter")
	}

	// Check if the IP matches the filter
	if ipFilter.Equal(ipAddr) {
		return true, nil
	}

	// If the filter is not a CIDR range or a single IP, return false
	return false, nil
}

func DeriveKey(secret string, info string) (string, error) {
	// Create hashing function
	hash := sha256.New

	// Create a new key using the secret and info
	hkdf := hkdf.New(hash, []byte(secret), nil, []byte(info)) // I am not using a salt because I just want two different keys from one secret, maybe bad practice

	// Create a new key
	key := make([]byte, 24)

	// Read the key from the HKDF
	_, err := io.ReadFull(hkdf, key)

	if err != nil {
		return "", err
	}

	// Verify the key is not empty
	if bytes.Equal(key, make([]byte, 24)) {
		return "", errors.New("derived key is empty")
	}

	// Encode the key to base64
	encodedKey := base64.StdEncoding.EncodeToString(key)

	// Return the key as a base64 encoded string
	return encodedKey, nil
}
