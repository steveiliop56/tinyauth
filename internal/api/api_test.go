package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"tinyauth/internal/api"
	"tinyauth/internal/auth"
	"tinyauth/internal/docker"
	"tinyauth/internal/handlers"
	"tinyauth/internal/hooks"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"

	"github.com/magiconair/properties/assert"
)

// Simple API config for tests
var apiConfig = types.APIConfig{
	Port:          8080,
	Address:       "0.0.0.0",
	Secret:        "super-secret-api-thing-for-tests", // It is 32 chars long
	CookieSecure:  false,
	SessionExpiry: 3600,
}

// Simple handlers config for tests
var handlersConfig = types.HandlersConfig{
	AppURL:          "http://localhost:8080",
	Domain:          ".localhost",
	CookieSecure:    false,
	DisableContinue: false,
	Title:           "Tinyauth",
	GenericName:     "Generic",
}

// Cookie
var cookie string

// User
var user = types.User{
	Username: "user",
	Password: "$2a$10$AvGHLTYv3xiRJ0xV9xs3XeVIlkGTygI9nqIamFYB5Xu.5.0UWF7B6", // pass
}

// We need all this to be able to test the API
func getAPI(t *testing.T) *api.API {
	// Create docker service
	docker := docker.NewDocker()

	// Initialize docker
	err := docker.Init()

	// Check if there was an error
	if err != nil {
		t.Fatalf("Failed to initialize docker: %v", err)
	}

	// Create auth service
	auth := auth.NewAuth(docker, types.Users{
		{
			Username: user.Username,
			Password: user.Password,
		},
	}, nil, apiConfig.SessionExpiry)

	// Create providers service
	providers := providers.NewProviders(types.OAuthConfig{})

	// Initialize providers
	providers.Init()

	// Create hooks service
	hooks := hooks.NewHooks(auth, providers)

	// Create handlers service
	handlers := handlers.NewHandlers(handlersConfig, auth, hooks, providers, docker)

	// Create API
	api := api.NewAPI(apiConfig, handlers)

	// Setup routes
	api.Init()
	api.SetupRoutes()

	return api
}

// Test login (we will need this for the other tests)
func TestLogin(t *testing.T) {
	t.Log("Testing login")

	// Get API
	api := getAPI(t)

	// Create recorder
	recorder := httptest.NewRecorder()

	// Create request
	user := types.LoginRequest{
		Username: "user",
		Password: "pass",
	}

	json, err := json.Marshal(user)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error marshalling json: %v", err)
	}

	// Create request
	req, err := http.NewRequest("POST", "/api/login", strings.NewReader(string(json)))

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	// Serve the request
	api.Router.ServeHTTP(recorder, req)

	// Assert
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Get the cookie
	cookie = recorder.Result().Cookies()[0].Value

	// Check if the cookie is set
	if cookie == "" {
		t.Fatalf("Cookie not set")
	}
}

// Test app context
func TestAppContext(t *testing.T) {
	t.Log("Testing app context")

	// Get API
	api := getAPI(t)

	// Create recorder
	recorder := httptest.NewRecorder()

	// Create request
	req, err := http.NewRequest("GET", "/api/app", nil)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	// Set the cookie
	req.AddCookie(&http.Cookie{
		Name:  "tinyauth",
		Value: cookie,
	})

	// Serve the request
	api.Router.ServeHTTP(recorder, req)

	// Assert
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Read the body of the response
	body, err := io.ReadAll(recorder.Body)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error getting body: %v", err)
	}

	// Unmarshal the body into the user struct
	var app types.AppContext

	err = json.Unmarshal(body, &app)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error unmarshalling body: %v", err)
	}

	// Create tests values
	expected := types.AppContext{
		Status:              200,
		Message:             "OK",
		ConfiguredProviders: []string{"username"},
		DisableContinue:     false,
		Title:               "Tinyauth",
		GenericName:         "Generic",
	}

	// We should get the username back
	if !reflect.DeepEqual(app, expected) {
		t.Fatalf("Expected %v, got %v", expected, app)
	}
}

// Test user context
func TestUserContext(t *testing.T) {
	t.Log("Testing user context")

	// Get API
	api := getAPI(t)

	// Create recorder
	recorder := httptest.NewRecorder()

	// Create request
	req, err := http.NewRequest("GET", "/api/user", nil)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	// Set the cookie
	req.AddCookie(&http.Cookie{
		Name:  "tinyauth",
		Value: cookie,
	})

	// Serve the request
	api.Router.ServeHTTP(recorder, req)

	// Assert
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Read the body of the response
	body, err := io.ReadAll(recorder.Body)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error getting body: %v", err)
	}

	// Unmarshal the body into the user struct
	type User struct {
		Username string `json:"username"`
	}

	var user User

	err = json.Unmarshal(body, &user)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error unmarshalling body: %v", err)
	}

	// We should get the username back
	if user.Username != "user" {
		t.Fatalf("Expected user, got %s", user.Username)
	}
}

// Test logout
func TestLogout(t *testing.T) {
	t.Log("Testing logout")

	// Get API
	api := getAPI(t)

	// Create recorder
	recorder := httptest.NewRecorder()

	// Create request
	req, err := http.NewRequest("POST", "/api/logout", nil)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	// Set the cookie
	req.AddCookie(&http.Cookie{
		Name:  "tinyauth",
		Value: cookie,
	})

	// Serve the request
	api.Router.ServeHTTP(recorder, req)

	// Assert
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Check if the cookie is different (means go sessions flushed it)
	if recorder.Result().Cookies()[0].Value == cookie {
		t.Fatalf("Cookie not flushed")
	}
}

// TODO: Testing for the oauth stuff
