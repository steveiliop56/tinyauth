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

// Simple server config
var serverConfig = types.ServerConfig{
	Port:    8080,
	Address: "0.0.0.0",
}

// Simple handlers config
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

// Simple auth config
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

// Simple hooks config
var hooksConfig = types.HooksConfig{
	Domain: "localhost",
}

// Cookie
var cookie string

// User
var user = types.User{
	Username: "user",
	Password: "$2a$10$AvGHLTYv3xiRJ0xV9xs3XeVIlkGTygI9nqIamFYB5Xu.5.0UWF7B6", // pass
}

// Initialize the server for tests
func getServer(t *testing.T) *server.Server {
	// Create services
	authConfig.Users = types.Users{
		{
			Username:   user.Username,
			Password:   user.Password,
			TotpSecret: user.TotpSecret,
		},
	}
	docker, err := docker.NewDocker()
	if err != nil {
		t.Fatalf("Failed to create docker client: %v", err)
	}
	auth := auth.NewAuth(authConfig, nil, nil)
	providers := providers.NewProviders(types.OAuthConfig{})
	hooks := hooks.NewHooks(hooksConfig, auth, providers)
	handlers := handlers.NewHandlers(handlersConfig, auth, hooks, providers, docker)

	// Create server
	srv, err := server.NewServer(serverConfig, handlers)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	return srv
}

func TestLogin(t *testing.T) {
	t.Log("Testing login")

	srv := getServer(t)

	recorder := httptest.NewRecorder()

	user := types.LoginRequest{
		Username: "user",
		Password: "pass",
	}

	json, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("Error marshalling json: %v", err)
	}

	req, err := http.NewRequest("POST", "/api/login", strings.NewReader(string(json)))
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	srv.Router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)

	cookies := recorder.Result().Cookies()

	if len(cookies) == 0 {
		t.Fatalf("Cookie not set")
	}

	// Set the cookie for further tests
	cookie = cookies[0].Value
}

func TestAppContext(t *testing.T) {
	// Refresh the cookie
	TestLogin(t)

	t.Log("Testing app context")

	srv := getServer(t)

	recorder := httptest.NewRecorder()

	req, err := http.NewRequest("GET", "/api/app", nil)
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	// Set the cookie from the previous test
	req.AddCookie(&http.Cookie{
		Name:  "tinyauth",
		Value: cookie,
	})

	srv.Router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)

	body, err := io.ReadAll(recorder.Body)
	if err != nil {
		t.Fatalf("Error getting body: %v", err)
	}

	var app types.AppContext

	err = json.Unmarshal(body, &app)
	if err != nil {
		t.Fatalf("Error unmarshalling body: %v", err)
	}

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

func TestUserContext(t *testing.T) {
	// Refresh the cookie
	TestLogin(t)

	t.Log("Testing user context")

	srv := getServer(t)

	recorder := httptest.NewRecorder()

	req, err := http.NewRequest("GET", "/api/user", nil)
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	req.AddCookie(&http.Cookie{
		Name:  "tinyauth-session",
		Value: cookie,
	})

	srv.Router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)

	body, err := io.ReadAll(recorder.Body)
	if err != nil {
		t.Fatalf("Error getting body: %v", err)
	}

	type User struct {
		Username string `json:"username"`
	}

	var user User

	err = json.Unmarshal(body, &user)
	if err != nil {
		t.Fatalf("Error unmarshalling body: %v", err)
	}

	// We should get the user back
	if user.Username != "user" {
		t.Fatalf("Expected user, got %s", user.Username)
	}
}

func TestLogout(t *testing.T) {
	// Refresh the cookie
	TestLogin(t)

	t.Log("Testing logout")

	srv := getServer(t)

	recorder := httptest.NewRecorder()

	req, err := http.NewRequest("POST", "/api/logout", nil)
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	req.AddCookie(&http.Cookie{
		Name:  "tinyauth-session",
		Value: cookie,
	})

	srv.Router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Check if the cookie is different (means the cookie is gone)
	if recorder.Result().Cookies()[0].Value == cookie {
		t.Fatalf("Cookie not flushed")
	}
}

func TestAuth(t *testing.T) {
	// Refresh the cookie
	TestLogin(t)

	t.Log("Testing auth endpoint")

	srv := getServer(t)

	recorder := httptest.NewRecorder()

	req, err := http.NewRequest("GET", "/api/auth/traefik", nil)
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	req.Header.Set("Accept", "text/html")

	srv.Router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusTemporaryRedirect)

	recorder = httptest.NewRecorder()

	req, err = http.NewRequest("GET", "/api/auth/traefik", nil)
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	req.AddCookie(&http.Cookie{
		Name:  "tinyauth-session",
		Value: cookie,
	})

	srv.Router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)

	recorder = httptest.NewRecorder()

	req, err = http.NewRequest("GET", "/api/auth/nginx", nil)
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	srv.Router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusUnauthorized)

	recorder = httptest.NewRecorder()

	req, err = http.NewRequest("GET", "/api/auth/nginx", nil)
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	req.AddCookie(&http.Cookie{
		Name:  "tinyauth-session",
		Value: cookie,
	})

	srv.Router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)
}

func TestTOTP(t *testing.T) {
	t.Log("Testing TOTP")

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Tinyauth",
		AccountName: user.Username,
	})
	if err != nil {
		t.Fatalf("Failed to generate TOTP secret: %v", err)
	}

	secret := key.Secret()

	user.TotpSecret = secret

	srv := getServer(t)

	user := types.LoginRequest{
		Username: "user",
		Password: "pass",
	}

	loginJson, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("Error marshalling json: %v", err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequest("POST", "/api/login", strings.NewReader(string(loginJson)))
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	srv.Router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Set the cookie for next test
	cookie = recorder.Result().Cookies()[0].Value

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	totpRequest := types.TotpRequest{
		Code: code,
	}

	totpJson, err := json.Marshal(totpRequest)
	if err != nil {
		t.Fatalf("Error marshalling TOTP request: %v", err)
	}

	recorder = httptest.NewRecorder()

	req, err = http.NewRequest("POST", "/api/totp", strings.NewReader(string(totpJson)))
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	req.AddCookie(&http.Cookie{
		Name:  "tinyauth-session",
		Value: cookie,
	})

	srv.Router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)
}
