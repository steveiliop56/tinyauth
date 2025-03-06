package utils_test

import (
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

// Test the get root url function
func TestGetRootURL(t *testing.T) {
	t.Log("Testing get root url with a valid url")

	// Test the get root url function with a valid url
	url := "https://sub1.sub2.domain.com:8080"
	expected := "sub2.domain.com"

	result, err := utils.GetRootURL(url)

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
	content := "user1:pass1\nuser2:pass2"
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
	err := os.WriteFile(file, []byte(expected), 0644)

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

// Test the tinyauth labels function
func TestGetTinyauthLabels(t *testing.T) {
	t.Log("Testing get tinyauth labels with a valid map")

	// Test the get tinyauth labels function with a valid map
	labels := map[string]string{
		"tinyauth.users":           "user1,user2",
		"tinyauth.oauth.whitelist": "user1,user2",
		"tinyauth.allowed":         "random",
		"random":                   "random",
	}

	expected := types.TinyauthLabels{
		Users:          []string{"user1", "user2"},
		OAuthWhitelist: []string{"user1", "user2"},
		Allowed:        "random",
	}

	result := utils.GetTinyauthLabels(labels)

	// Check if the result is equal to the expected
	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v, got %v", expected, result)
	}
}

// Test the filter function
func TestFilter(t *testing.T) {
	t.Log("Testing filter helper")

	// Create variables
	data := []string{"", "val1", "", "val2", "", "val3", ""}
	expected := []string{"val1", "val2", "val3"}

	// Test the filter function
	result := utils.Filter(data, func(val string) bool {
		return val != ""
	})

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
