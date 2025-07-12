package utils_test

import (
	"fmt"
	"os"
	"reflect"
	"testing"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"
)

func TestParseUsers(t *testing.T) {
	t.Log("Testing parse users with a valid string")

	users := "user1:pass1,user2:pass2"
	expected := types.Users{
		{
			Username: "user1",
			Password: "pass1",
		},
		{
			Username: "user2",
			Password: "pass2",
		},
	}

	result, err := utils.ParseUsers(users)
	if err != nil {
		t.Fatalf("Error parsing users: %v", err)
	}

	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

func TestGetUpperDomain(t *testing.T) {
	t.Log("Testing get upper domain with a valid url")

	url := "https://sub1.sub2.domain.com:8080"
	expected := "sub2.domain.com"

	result, err := utils.GetUpperDomain(url)
	if err != nil {
		t.Fatalf("Error getting root url: %v", err)
	}

	if expected != result {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

func TestReadFile(t *testing.T) {
	t.Log("Creating a test file")

	err := os.WriteFile("/tmp/test.txt", []byte("test"), 0644)
	if err != nil {
		t.Fatalf("Error creating test file: %v", err)
	}

	t.Log("Testing read file with a valid file")

	data, err := utils.ReadFile("/tmp/test.txt")
	if err != nil {
		t.Fatalf("Error reading file: %v", err)
	}

	if data != "test" {
		t.Fatalf("Expected test, got %v", data)
	}

	t.Log("Cleaning up test file")

	err = os.Remove("/tmp/test.txt")
	if err != nil {
		t.Fatalf("Error cleaning up test file: %v", err)
	}
}

func TestParseFileToLine(t *testing.T) {
	t.Log("Testing parse file to line with a valid string")

	content := "\nuser1:pass1\nuser2:pass2\n"
	expected := "user1:pass1,user2:pass2"

	result := utils.ParseFileToLine(content)

	if expected != result {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

func TestGetSecret(t *testing.T) {
	t.Log("Testing get secret with an empty config and file")

	conf := ""
	file := "/tmp/test.txt"
	expected := "test"

	err := os.WriteFile(file, []byte(fmt.Sprintf("\n\n    \n\n\n  %s   \n\n    \n  ", expected)), 0644)
	if err != nil {
		t.Fatalf("Error creating test file: %v", err)
	}

	result := utils.GetSecret(conf, file)

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing get secret with an empty file and a valid config")

	result = utils.GetSecret(expected, "")

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing get secret with both a valid config and file")

	result = utils.GetSecret(expected, file)

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Cleaning up test file")

	err = os.Remove(file)
	if err != nil {
		t.Fatalf("Error cleaning up test file: %v", err)
	}
}

func TestGetUsers(t *testing.T) {
	t.Log("Testing get users with a config and no file")

	conf := "user1:pass1,user2:pass2"
	file := ""
	expected := types.Users{
		{
			Username: "user1",
			Password: "pass1",
		},
		{
			Username: "user2",
			Password: "pass2",
		},
	}

	result, err := utils.GetUsers(conf, file)
	if err != nil {
		t.Fatalf("Error getting users: %v", err)
	}

	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing get users with a file and no config")

	conf = ""
	file = "/tmp/test.txt"
	expected = types.Users{
		{
			Username: "user1",
			Password: "pass1",
		},
		{
			Username: "user2",
			Password: "pass2",
		},
	}

	err = os.WriteFile(file, []byte("user1:pass1\nuser2:pass2"), 0644)
	if err != nil {
		t.Fatalf("Error creating test file: %v", err)
	}

	result, err = utils.GetUsers(conf, file)
	if err != nil {
		t.Fatalf("Error getting users: %v", err)
	}

	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing get users with both a config and file")

	conf = "user3:pass3"
	expected = types.Users{
		{
			Username: "user3",
			Password: "pass3",
		},
		{
			Username: "user1",
			Password: "pass1",
		},
		{
			Username: "user2",
			Password: "pass2",
		},
	}

	result, err = utils.GetUsers(conf, file)
	if err != nil {
		t.Fatalf("Error getting users: %v", err)
	}

	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Cleaning up test file")

	err = os.Remove(file)
	if err != nil {
		t.Fatalf("Error cleaning up test file: %v", err)
	}
}

func TestGetLabels(t *testing.T) {
	t.Log("Testing get labels with a valid map")

	labels := map[string]string{
		"tinyauth.users":           "user1,user2",
		"tinyauth.oauth.whitelist": "/regex/",
		"tinyauth.allowed":         "random",
		"tinyauth.headers":         "X-Header=value",
		"tinyauth.oauth.groups":    "group1,group2",
	}

	expected := types.Labels{
		Users:   "user1,user2",
		Allowed: "random",
		Headers: []string{"X-Header=value"},
		OAuth: types.OAuthLabels{
			Whitelist: "/regex/",
			Groups:    "group1,group2",
		},
	}

	result, err := utils.GetLabels(labels)
	if err != nil {
		t.Fatalf("Error getting labels: %v", err)
	}

	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

func TestParseUser(t *testing.T) {
	t.Log("Testing parse user with a valid user")

	user := "user:pass:secret"
	expected := types.User{
		Username:   "user",
		Password:   "pass",
		TotpSecret: "secret",
	}

	result, err := utils.ParseUser(user)
	if err != nil {
		t.Fatalf("Error parsing user: %v", err)
	}

	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing parse user with an escaped user")

	user = "user:p$$ass$$:secret"
	expected = types.User{
		Username:   "user",
		Password:   "p$ass$",
		TotpSecret: "secret",
	}

	result, err = utils.ParseUser(user)
	if err != nil {
		t.Fatalf("Error parsing user: %v", err)
	}

	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing parse user with an invalid user")

	user = "user::pass"

	_, err = utils.ParseUser(user)
	if err == nil {
		t.Fatalf("Expected error parsing user")
	}
}

func TestCheckFilter(t *testing.T) {
	t.Log("Testing check filter with a comma separated list")

	filter := "user1,user2,user3"
	str := "user1"
	expected := true

	result := utils.CheckFilter(filter, str)

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing check filter with a regex filter")

	filter = "/^user[0-9]+$/"
	str = "user1"
	expected = true

	result = utils.CheckFilter(filter, str)

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing check filter with an empty filter")

	filter = ""
	str = "user1"
	expected = true

	result = utils.CheckFilter(filter, str)

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing check filter with an invalid regex filter")

	filter = "/^user[0-9+$/"
	str = "user1"
	expected = false

	result = utils.CheckFilter(filter, str)

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing check filter with a non matching list")

	filter = "user1,user2,user3"
	str = "user4"
	expected = false

	result = utils.CheckFilter(filter, str)

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

func TestSanitizeHeader(t *testing.T) {
	t.Log("Testing sanitize header with a valid string")

	str := "X-Header=value"
	expected := "X-Header=value"

	result := utils.SanitizeHeader(str)

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing sanitize header with an invalid string")

	str = "X-Header=val\nue"
	expected = "X-Header=value"

	result = utils.SanitizeHeader(str)

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

func TestParseHeaders(t *testing.T) {
	t.Log("Testing parse headers with a valid string")

	headers := []string{"X-Hea\x00der1=value1", "X-Header2=value\n2"}
	expected := map[string]string{
		"X-Header1": "value1",
		"X-Header2": "value2",
	}

	result := utils.ParseHeaders(headers)

	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing parse headers with an invalid string")

	headers = []string{"X-Header1=", "X-Header2", "=value", "X-Header3=value3"}
	expected = map[string]string{"X-Header3": "value3"}

	result = utils.ParseHeaders(headers)

	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

func TestParseSecretFile(t *testing.T) {
	t.Log("Testing parse secret file with a valid file")

	content := "\n\n    \n\n\n  secret   \n\n    \n  "
	expected := "secret"

	result := utils.ParseSecretFile(content)

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

func TestFilterIP(t *testing.T) {
	t.Log("Testing filter IP with an IP and a valid CIDR")

	ip := "10.10.10.10"
	filter := "10.10.10.0/24"
	expected := true

	result, err := utils.FilterIP(filter, ip)
	if err != nil {
		t.Fatalf("Error filtering IP: %v", err)
	}

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing filter IP with an IP and a valid IP")

	filter = "10.10.10.10"
	expected = true

	result, err = utils.FilterIP(filter, ip)
	if err != nil {
		t.Fatalf("Error filtering IP: %v", err)
	}

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing filter IP with an IP and an non matching CIDR")

	filter = "10.10.15.0/24"
	expected = false

	result, err = utils.FilterIP(filter, ip)
	if err != nil {
		t.Fatalf("Error filtering IP: %v", err)
	}

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing filter IP with a non matching IP and a valid CIDR")

	filter = "10.10.10.11"
	expected = false

	result, err = utils.FilterIP(filter, ip)

	if err != nil {
		t.Fatalf("Error filtering IP: %v", err)
	}

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing filter IP with an IP and an invalid CIDR")

	filter = "10.../83"

	_, err = utils.FilterIP(filter, ip)
	if err == nil {
		t.Fatalf("Expected error filtering IP")
	}
}

func TestDeriveKey(t *testing.T) {
	t.Log("Testing the derive key function")

	master := "master"
	info := "info"
	expected := "gdrdU/fXzclYjiSXRexEatVgV13qQmKl"

	result, err := utils.DeriveKey(master, info)

	if err != nil {
		t.Fatalf("Error deriving key: %v", err)
	}

	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}
