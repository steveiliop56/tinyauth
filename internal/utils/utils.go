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

	var usersParsed types.Users

	userList := strings.Split(users, ",")

	if len(userList) == 0 {
		return types.Users{}, errors.New("invalid user format")
	}

	for _, user := range userList {
		parsed, err := ParseUser(user)
		if err != nil {
			return types.Users{}, err
		}
		usersParsed = append(usersParsed, parsed)
	}

	log.Debug().Msg("Parsed users")
	return usersParsed, nil
}

// Get upper domain parses a hostname and returns the upper domain (e.g. sub1.sub2.domain.com -> sub2.domain.com)
func GetUpperDomain(urlSrc string) (string, error) {
	urlParsed, err := url.Parse(urlSrc)
	if err != nil {
		return "", err
	}

	urlSplitted := strings.Split(urlParsed.Hostname(), ".")
	urlFinal := strings.Join(urlSplitted[1:], ".")

	return urlFinal, nil
}

// Reads a file and returns the contents
func ReadFile(file string) (string, error) {
	_, err := os.Stat(file)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// Parses a file into a comma separated list of users
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

// Get the secret from the config or file
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

	return ParseSecretFile(contents)
}

// Get the users from the config or file
func GetUsers(conf string, file string) (types.Users, error) {
	var users string

	if conf == "" && file == "" {
		return types.Users{}, nil
	}

	if conf != "" {
		log.Debug().Msg("Using users from config")
		users += conf
	}

	if file != "" {
		contents, err := ReadFile(file)
		if err == nil {
			log.Debug().Msg("Using users from file")
			if users != "" {
				users += ","
			}
			users += ParseFileToLine(contents)
		}
	}

	return ParseUsers(users)
}

// Parse the headers in a map[string]string format
func ParseHeaders(headers []string) map[string]string {
	headerMap := make(map[string]string)

	for _, header := range headers {
		split := strings.SplitN(header, "=", 2)
		if len(split) != 2 || strings.TrimSpace(split[0]) == "" || strings.TrimSpace(split[1]) == "" {
			log.Warn().Str("header", header).Msg("Invalid header format, skipping")
			continue
		}
		key := SanitizeHeader(strings.TrimSpace(split[0]))
		value := SanitizeHeader(strings.TrimSpace(split[1]))
		headerMap[key] = value
	}

	return headerMap
}

// Get labels parses a map of labels into a struct with only the needed labels
func GetLabels(labels map[string]string) (types.Labels, error) {
	var labelsParsed types.Labels

	err := parser.Decode(labels, &labelsParsed, "tinyauth", "tinyauth.users", "tinyauth.allowed", "tinyauth.headers", "tinyauth.domain", "tinyauth.basic", "tinyauth.oauth", "tinyauth.ip")
	if err != nil {
		log.Error().Err(err).Msg("Error parsing labels")
		return types.Labels{}, err
	}

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
	if strings.Contains(user, "$$") {
		user = strings.ReplaceAll(user, "$$", "$")
	}

	userSplit := strings.Split(user, ":")

	if len(userSplit) < 2 || len(userSplit) > 3 {
		return types.User{}, errors.New("invalid user format")
	}

	for _, userPart := range userSplit {
		if strings.TrimSpace(userPart) == "" {
			return types.User{}, errors.New("invalid user format")
		}
	}

	if len(userSplit) == 2 {
		return types.User{
			Username: strings.TrimSpace(userSplit[0]),
			Password: strings.TrimSpace(userSplit[1]),
		}, nil
	}

	return types.User{
		Username:   strings.TrimSpace(userSplit[0]),
		Password:   strings.TrimSpace(userSplit[1]),
		TotpSecret: strings.TrimSpace(userSplit[2]),
	}, nil
}

// Parse secret file
func ParseSecretFile(contents string) string {
	lines := strings.Split(contents, "\n")

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		return strings.TrimSpace(line)
	}

	return ""
}

// Check if a string matches a regex or if it is included in a comma separated list
func CheckFilter(filter string, str string) bool {
	if len(strings.TrimSpace(filter)) == 0 {
		return true
	}

	if strings.HasPrefix(filter, "/") && strings.HasSuffix(filter, "/") {
		re, err := regexp.Compile(filter[1 : len(filter)-1])
		if err != nil {
			log.Error().Err(err).Msg("Error compiling regex")
			return false
		}

		if re.MatchString(str) {
			return true
		}
	}

	filterSplit := strings.Split(filter, ",")

	for _, item := range filterSplit {
		if strings.TrimSpace(item) == str {
			return true
		}
	}

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
	uuid := uuid.NewSHA1(uuid.NameSpaceURL, []byte(str))
	uuidString := uuid.String()
	log.Debug().Str("uuid", uuidString).Msg("Generated UUID")
	return strings.Split(uuidString, "-")[0]
}

// Get a basic auth header from a username and password
func GetBasicAuth(username string, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// Check if an IP is contained in a CIDR range/matches a single IP
func FilterIP(filter string, ip string) (bool, error) {
	ipAddr := net.ParseIP(ip)

	if strings.Contains(filter, "/") {
		_, cidr, err := net.ParseCIDR(filter)
		if err != nil {
			return false, err
		}
		return cidr.Contains(ipAddr), nil
	}

	ipFilter := net.ParseIP(filter)
	if ipFilter == nil {
		return false, errors.New("invalid IP address in filter")
	}

	if ipFilter.Equal(ipAddr) {
		return true, nil
	}

	return false, nil
}

func DeriveKey(secret string, info string) (string, error) {
	hash := sha256.New
	hkdf := hkdf.New(hash, []byte(secret), nil, []byte(info)) // I am not using a salt because I just want two different keys from one secret, maybe bad practice
	key := make([]byte, 24)

	_, err := io.ReadFull(hkdf, key)
	if err != nil {
		return "", err
	}

	if bytes.Equal(key, make([]byte, 24)) {
		return "", errors.New("derived key is empty")
	}

	encodedKey := base64.StdEncoding.EncodeToString(key)
	return encodedKey, nil
}
