package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
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

func GenerateIdentifier(str string) string {
	uuid := uuid.NewSHA1(uuid.NameSpaceURL, []byte(str))
	uuidString := uuid.String()
	return strings.Split(uuidString, "-")[0]
}
