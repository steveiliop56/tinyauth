package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
	"tinyauth/internal/auth"
	"tinyauth/internal/docker"
	"tinyauth/internal/handlers"
	"tinyauth/internal/hooks"
	"tinyauth/internal/providers"
	"tinyauth/internal/server"
	"tinyauth/internal/types"

	"github.com/magiconair/properties/assert"
	"github.com/pquerna/otp/totp"
)

// Simple server config for tests
var serverConfig = types.ServerConfig{
	Port:    8080,
	Address: "0.0.0.0",
}

// Simple handlers config for tests
var handlersConfig = types.HandlersConfig{
	AppURL:                "http://localhost:8080",
	Domain:                "localhost",
	DisableContinue:       false,
	CookieSecure:          false,
	Title:                 "Tinyauth",
	GenericName:           "Generic",
	ForgotPasswordMessage: "Message",
	CsrfCookieName:        "tinyauth-csrf",
	RedirectCookieName:    "tinyauth-redirect",
	BackgroundImage:       "https://example.com/image.png",
	OAuthAutoRedirect:     "none",
}

// Simple auth config for tests
var authConfig = types.AuthConfig{
	Users:             types.Users{},
	OauthWhitelist:    "",
	HMACSecret:        "4bZ9K.*:;zH=,9zG!meUxu.B5-S[7.V.", // Complex on purpose
	EncryptionSecret:  "\\:!R(u[Sbv6ZLm.7es)H|OqH4y}0u\\rj",
	CookieSecure:      false,
	SessionExpiry:     3600,
	LoginTimeout:      0,
	LoginMaxRetries:   0,
	SessionCookieName: "tinyauth-session",
	Domain:            "localhost",
}

// Simple hooks config for tests
var hooksConfig = types.HooksConfig{
	Domain: "localhost",
}

// Cookie
var cookie = "MTc1MTkyMzM5MnxiME9aTzlGQjZMNEJMdDZMc0lHMk9zcXQyME9SR1ZnUmlaYWZNcWplek5vcVNpdkdHRTZqb09YWkVUYUN6NEt4MkEyOGEyX2hFQWZEUEYtbllDX0h5eDBCb3VyT2phQlRpZWFfRFdTMGw2WUg2VWw4RGdNbEhQclotOUJjblJGaWFQcmhyaWFna0dXRWNud2c1akg5eEpLZ3JzS0pfWktscVZyckZFR1VDX0R5QjFOT0hzMTNKb18ySEMxZlluSWNxa1ByM0VhSzNyMkRtdDNORWJXVGFYSnMzWjFGa0lrZlhSTWduRmttMHhQUXN4UFhNbHFXY0lBWjBnUWpKU0xXMHRubjlKbjV0LXBGdjk0MmpJX0xMX1ZYblVJVW9LWUJoWmpNanVXNkNjamhYWlR2V29rY0RNYWkxY2lMQnpqLUI2cHMyYTZkWWgtWnlFdGN0amh2WURUeUNGT3ZLS1FJVUFIb0NWR1RPMlRtY2c9PXwerwFtb9urOXnwA02qXbLeorMloaK_paQd0in4BAesmg=="

// User
var user = types.User{
	Username: "user",
	Password: "$2a$10$AvGHLTYv3xiRJ0xV9xs3XeVIlkGTygI9nqIamFYB5Xu.5.0UWF7B6", // pass
}

// Initialize the server for tests
func getServer(t *testing.T) *server.Server {
	// Create docker service
	docker, err := docker.NewDocker()

	if err != nil {
		t.Fatalf("Failed to initialize docker: %v", err)
	}

	// Create auth service
	authConfig.Users = types.Users{
		{
			Username:   user.Username,
			Password:   user.Password,
			TotpSecret: user.TotpSecret,
		},
	}
	auth := auth.NewAuth(authConfig, docker, nil)

	// Create providers service
	providers := providers.NewProviders(types.OAuthConfig{})

	// Create hooks service
	hooks := hooks.NewHooks(hooksConfig, auth, providers)

	// Create handlers service
	handlers := handlers.NewHandlers(handlersConfig, auth, hooks, providers, docker)

	// Create server
	srv, err := server.NewServer(serverConfig, handlers)

	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Return the server
	return srv
}

// Test login
func TestLogin(t *testing.T) {
	t.Log("Testing login")

	// Get server
	srv := getServer(t)

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
	srv.Router.ServeHTTP(recorder, req)

	// Assert
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Get the result cookie
	cookies := recorder.Result().Cookies()

	// Check if the cookie is set
	if len(cookies) == 0 {
		t.Fatalf("Cookie not set")
	}

	// Set the cookie for further tests
	cookie = cookies[0].Value
}

// Test app context
func TestAppContext(t *testing.T) {
	t.Log("Testing app context")

	// Get server
	srv := getServer(t)

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
	srv.Router.ServeHTTP(recorder, req)

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
		Status:                200,
		Message:               "OK",
		ConfiguredProviders:   []string{"username"},
		DisableContinue:       false,
		Title:                 "Tinyauth",
		GenericName:           "Generic",
		ForgotPasswordMessage: "Message",
		BackgroundImage:       "https://example.com/image.png",
		OAuthAutoRedirect:     "none",
		Domain:                "localhost",
	}

	// We should get the username back
	if !reflect.DeepEqual(app, expected) {
		t.Fatalf("Expected %v, got %v", expected, app)
	}
}

// Test user context
func TestUserContext(t *testing.T) {
	// Refresh the cookie
	TestLogin(t)

	t.Log("Testing user context")

	// Get server
	srv := getServer(t)

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
		Name:  "tinyauth-session",
		Value: cookie,
	})

	// Serve the request
	srv.Router.ServeHTTP(recorder, req)

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
	// Refresh the cookie
	TestLogin(t)

	t.Log("Testing logout")

	// Get server
	srv := getServer(t)

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
		Name:  "tinyauth-session",
		Value: cookie,
	})

	// Serve the request
	srv.Router.ServeHTTP(recorder, req)

	// Assert
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Check if the cookie is different (means the cookie is gone)
	if recorder.Result().Cookies()[0].Value == cookie {
		t.Fatalf("Cookie not flushed")
	}
}

// Test auth endpoint
func TestAuth(t *testing.T) {
	// Refresh the cookie
	TestLogin(t)

	t.Log("Testing auth endpoint")

	// Get server
	srv := getServer(t)

	// Create recorder
	recorder := httptest.NewRecorder()

	// Create request
	req, err := http.NewRequest("GET", "/api/auth/traefik", nil)

	// Set the accept header
	req.Header.Set("Accept", "text/html")

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	// Serve the request
	srv.Router.ServeHTTP(recorder, req)

	// Assert
	assert.Equal(t, recorder.Code, http.StatusTemporaryRedirect)

	// Recreate recorder
	recorder = httptest.NewRecorder()

	// Recreate the request
	req, err = http.NewRequest("GET", "/api/auth/traefik", nil)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	// Test with the cookie
	req.AddCookie(&http.Cookie{
		Name:  "tinyauth-session",
		Value: cookie,
	})

	// Serve the request again
	srv.Router.ServeHTTP(recorder, req)

	// Assert
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Recreate recorder
	recorder = httptest.NewRecorder()

	// Recreate the request
	req, err = http.NewRequest("GET", "/api/auth/nginx", nil)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	// Serve the request again
	srv.Router.ServeHTTP(recorder, req)

	// Assert
	assert.Equal(t, recorder.Code, http.StatusUnauthorized)

	// Recreate recorder
	recorder = httptest.NewRecorder()

	// Recreate the request
	req, err = http.NewRequest("GET", "/api/auth/nginx", nil)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	// Test with the cookie
	req.AddCookie(&http.Cookie{
		Name:  "tinyauth-session",
		Value: cookie,
	})

	// Serve the request again
	srv.Router.ServeHTTP(recorder, req)

	// Assert
	assert.Equal(t, recorder.Code, http.StatusOK)
}

func TestTOTP(t *testing.T) {
	t.Log("Testing TOTP")

	// Generate totp secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Tinyauth",
		AccountName: user.Username,
	})

	if err != nil {
		t.Fatalf("Failed to generate TOTP secret: %v", err)
	}

	// Create secret
	secret := key.Secret()

	// Set the user's TOTP secret
	user.TotpSecret = secret

	// Get server
	srv := getServer(t)

	// Create request
	user := types.LoginRequest{
		Username: "user",
		Password: "pass",
	}

	loginJson, err := json.Marshal(user)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error marshalling json: %v", err)
	}

	// Create recorder
	recorder := httptest.NewRecorder()

	// Create request
	req, err := http.NewRequest("POST", "/api/login", strings.NewReader(string(loginJson)))

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	// Serve the request
	srv.Router.ServeHTTP(recorder, req)

	// Assert
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Set the cookie for next test
	cookie = recorder.Result().Cookies()[0].Value

	// Create TOTP code
	code, err := totp.GenerateCode(secret, time.Now())

	// Check if there was an error
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	// Create TOTP request
	totpRequest := types.TotpRequest{
		Code: code,
	}

	// Marshal the TOTP request
	totpJson, err := json.Marshal(totpRequest)

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error marshalling TOTP request: %v", err)
	}

	// Create recorder
	recorder = httptest.NewRecorder()

	// Create request
	req, err = http.NewRequest("POST", "/api/totp", strings.NewReader(string(totpJson)))

	// Check if there was an error
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	// Set the cookie
	req.AddCookie(&http.Cookie{
		Name:  "tinyauth-session",
		Value: cookie,
	})

	// Serve the request
	srv.Router.ServeHTTP(recorder, req)

	// Assert
	assert.Equal(t, recorder.Code, http.StatusOK)
}
