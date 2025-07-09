package utils_test

import (
	"fmt"
	"os"
	"reflect"
	"testing"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"
)

// Test the parse users function
func TestParseUsers(t *testing.T) {
	t.Log("Testing parse users with a valid string")

	// Test the parse users function with a valid string
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

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error parsing users: %v", err)
	}

	// Check if the result is equal to the expected
	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

// Test the get upper domain function
func TestGetUpperDomain(t *testing.T) {
	t.Log("Testing get upper domain with a valid url")

	// Test the get upper domain function with a valid url
	url := "https://sub1.sub2.domain.com:8080"
	expected := "sub2.domain.com"

	result, err := utils.GetUpperDomain(url)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error getting root url: %v", err)
	}

	// Check if the result is equal to the expected
	if expected != result {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

// Test the read file function
func TestReadFile(t *testing.T) {
	t.Log("Creating a test file")

	// Create a test file
	err := os.WriteFile("/tmp/test.txt", []byte("test"), 0644)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error creating test file: %v", err)
	}

	// Test the read file function
	t.Log("Testing read file with a valid file")

	data, err := utils.ReadFile("/tmp/test.txt")

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error reading file: %v", err)
	}

	// Check if the data is equal to the expected
	if data != "test" {
		t.Fatalf("Expected test, got %v", data)
	}

	// Cleanup the test file
	t.Log("Cleaning up test file")

	err = os.Remove("/tmp/test.txt")

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error cleaning up test file: %v", err)
	}
}

// Test the parse file to line function
func TestParseFileToLine(t *testing.T) {
	t.Log("Testing parse file to line with a valid string")

	// Test the parse file to line function with a valid string
	content := "\nuser1:pass1\nuser2:pass2\n"
	expected := "user1:pass1,user2:pass2"

	result := utils.ParseFileToLine(content)

	// Check if the result is equal to the expected
	if expected != result {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

// Test the get secret function
func TestGetSecret(t *testing.T) {
	t.Log("Testing get secret with an empty config and file")

	// Test the get secret function with an empty config and file
	conf := ""
	file := "/tmp/test.txt"
	expected := "test"

	// Create file
	err := os.WriteFile(file, []byte(fmt.Sprintf("\n\n    \n\n\n  %s   \n\n    \n  ", expected)), 0644)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error creating test file: %v", err)
	}

	// Test
	result := utils.GetSecret(conf, file)

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing get secret with an empty file and a valid config")

	// Test the get secret function with an empty file and a valid config
	result = utils.GetSecret(expected, "")

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing get secret with both a valid config and file")

	// Test the get secret function with both a valid config and file
	result = utils.GetSecret(expected, file)

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	// Cleanup the test file
	t.Log("Cleaning up test file")

	err = os.Remove(file)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error cleaning up test file: %v", err)
	}
}

// Test the get users function
func TestGetUsers(t *testing.T) {
	t.Log("Testing get users with a config and no file")

	// Test the get users function with a config and no file
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

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error getting users: %v", err)
	}

	// Check if the result is equal to the expected
	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing get users with a file and no config")

	// Test the get users function with a file and no config
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

	// Create file
	err = os.WriteFile(file, []byte("user1:pass1\nuser2:pass2"), 0644)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error creating test file: %v", err)
	}

	// Test
	result, err = utils.GetUsers(conf, file)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error getting users: %v", err)
	}

	// Check if the result is equal to the expected
	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	// Test the get users function with both a config and file
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

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error getting users: %v", err)
	}

	// Check if the result is equal to the expected
	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	// Cleanup the test file
	t.Log("Cleaning up test file")

	err = os.Remove(file)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error cleaning up test file: %v", err)
	}
}

// Test the get labels function
func TestGetLabels(t *testing.T) {
	t.Log("Testing get labels with a valid map")

	// Test the get tinyauth labels function with a valid map
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

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error getting labels: %v", err)
	}

	// Check if the result is equal to the expected
	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

// Test parse user
func TestParseUser(t *testing.T) {
	t.Log("Testing parse user with a valid user")

	// Create variables
	user := "user:pass:secret"
	expected := types.User{
		Username:   "user",
		Password:   "pass",
		TotpSecret: "secret",
	}

	// Test the parse user function
	result, err := utils.ParseUser(user)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error parsing user: %v", err)
	}

	// Check if the result is equal to the expected
	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing parse user with an escaped user")

	// Create variables
	user = "user:p$$ass$$:secret"
	expected = types.User{
		Username:   "user",
		Password:   "p$ass$",
		TotpSecret: "secret",
	}

	// Test the parse user function
	result, err = utils.ParseUser(user)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error parsing user: %v", err)
	}

	// Check if the result is equal to the expected
	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing parse user with an invalid user")

	// Create variables
	user = "user::pass"

	// Test the parse user function
	_, err = utils.ParseUser(user)

	// Check if there was an error
	if err == nil {
		t.Fatalf("Expected error parsing user")
	}
}

// Test the check filter function
func TestCheckFilter(t *testing.T) {
	t.Log("Testing check filter with a comma separated list")

	// Create variables
	filter := "user1,user2,user3"
	str := "user1"
	expected := true

	// Test the check filter function
	result := utils.CheckFilter(filter, str, false)

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing check filter with a regex filter")

	// Create variables
	filter = "/^user[0-9]+$/"
	str = "user1"
	expected = true

	// Test the check filter function
	result = utils.CheckFilter(filter, str, true)

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing check filter with an empty filter")

	// Create variables
	filter = ""
	str = "user1"
	expected = true

	// Test the check filter function
	result = utils.CheckFilter(filter, str, false)

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing check filter with an invalid regex filter")

	// Create variables
	filter = "/^user[0-9+$/"
	str = "user1"
	expected = false

	// Test the check filter function
	result = utils.CheckFilter(filter, str, true)

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing check filter with a non matching list")

	// Create variables
	filter = "user1,user2,user3"
	str = "user4"
	expected = false

	// Test the check filter function
	result = utils.CheckFilter(filter, str, false)

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

// Test the header sanitizer
func TestSanitizeHeader(t *testing.T) {
	t.Log("Testing sanitize header with a valid string")

	// Create variables
	str := "X-Header=value"
	expected := "X-Header=value"

	// Test the sanitize header function
	result := utils.SanitizeHeader(str)

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing sanitize header with an invalid string")

	// Create variables
	str = "X-Header=val\nue"
	expected = "X-Header=value"

	// Test the sanitize header function
	result = utils.SanitizeHeader(str)

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

// Test the parse headers function
func TestParseHeaders(t *testing.T) {
	t.Log("Testing parse headers with a valid string")

	// Create variables
	headers := []string{"X-Hea\x00der1=value1", "X-Header2=value\n2"}
	expected := map[string]string{
		"X-Header1": "value1",
		"X-Header2": "value2",
	}

	// Test the parse headers function
	result := utils.ParseHeaders(headers)

	// Check if the result is equal to the expected
	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing parse headers with an invalid string")

	// Create variables
	headers = []string{"X-Header1=", "X-Header2", "=value", "X-Header3=value3"}
	expected = map[string]string{"X-Header3": "value3"}

	// Test the parse headers function
	result = utils.ParseHeaders(headers)

	// Check if the result is equal to the expected
	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

// Test the parse secret file function
func TestParseSecretFile(t *testing.T) {
	t.Log("Testing parse secret file with a valid file")

	// Create variables
	content := "\n\n    \n\n\n  secret   \n\n    \n  "
	expected := "secret"

	// Test the parse secret file function
	result := utils.ParseSecretFile(content)

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

// Test the filter IP function
func TestFilterIP(t *testing.T) {
	t.Log("Testing filter IP with an IP and a valid CIDR")

	// Create variables
	ip := "10.10.10.10"
	filter := "10.10.10.0/24"
	expected := true

	// Test the filter IP function
	result, err := utils.FilterIP(filter, ip)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error filtering IP: %v", err)
	}

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing filter IP with an IP and a valid IP")

	// Create variables
	filter = "10.10.10.10"
	expected = true

	// Test the filter IP function
	result, err = utils.FilterIP(filter, ip)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error filtering IP: %v", err)
	}

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing filter IP with an IP and an non matching CIDR")

	// Create variables
	filter = "10.10.15.0/24"
	expected = false

	// Test the filter IP function
	result, err = utils.FilterIP(filter, ip)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error filtering IP: %v", err)
	}

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing filter IP with a non matching IP and a valid CIDR")

	// Create variables
	filter = "10.10.10.11"
	expected = false

	// Test the filter IP function
	result, err = utils.FilterIP(filter, ip)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error filtering IP: %v", err)
	}

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}

	t.Log("Testing filter IP with an IP and an invalid CIDR")

	// Create variables
	filter = "10.../83"

	// Test the filter IP function
	_, err = utils.FilterIP(filter, ip)

	// Check if there was an error
	if err == nil {
		t.Fatalf("Expected error filtering IP")
	}
}

// Test the derive key function
func TestDeriveKey(t *testing.T) {
	t.Log("Testing the derive key function")

	// Create variables
	master := "master"
	info := "info"
	expected := "gdrdU/fXzclYjiSXRexEatVgV13qQmKl"

	// Test the derive key function
	result, err := utils.DeriveKey(master, info)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error deriving key: %v", err)
	}

	// Check if the result is equal to the expected
	if result != expected {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}
