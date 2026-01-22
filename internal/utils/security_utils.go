package utils

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math"
	"math/big"
	"net"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

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

func GetBasicAuth(username string, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func FilterIP(filter string, ip string) (bool, error) {
	ipAddr := net.ParseIP(ip)

	if ipAddr == nil {
		return false, errors.New("invalid IP address")
	}

	filter = strings.Replace(filter, "-", "/", -1)

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

func CheckFilter(filter string, str string) bool {
	if len(strings.TrimSpace(filter)) == 0 {
		return true
	}

	if strings.HasPrefix(filter, "/") && strings.HasSuffix(filter, "/") {
		re, err := regexp.Compile(filter[1 : len(filter)-1])
		if err != nil {
			return false
		}

		if re.MatchString(strings.TrimSpace(str)) {
			return true
		}
	}

	filterSplit := strings.Split(filter, ",")

	for _, item := range filterSplit {
		if strings.TrimSpace(item) == strings.TrimSpace(str) {
			return true
		}
	}

	return false
}

func GenerateUUID(str string) string {
	uuid := uuid.NewSHA1(uuid.NameSpaceURL, []byte(str))
	return uuid.String()
}

// These could definitely be improved A LOT but at least they are cryptographically secure
func GetRandomString(length int) (string, error) {
	if length < 1 {
		return "", errors.New("length must be greater than 0")
	}
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	state := base64.RawURLEncoding.EncodeToString(b)
	return state[:length], nil
}

func GetRandomInt(length int) (int64, error) {
	if length < 1 {
		return 0, errors.New("length must be greater than 0")
	}
	a, err := rand.Int(rand.Reader, big.NewInt(int64(math.Pow(10, float64(length)))))
	if err != nil {
		return 0, err
	}
	return a.Int64(), nil
}
