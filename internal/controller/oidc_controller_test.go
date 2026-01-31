package controller_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/steveiliop56/tinyauth/internal/bootstrap"
	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/controller"
	"github.com/steveiliop56/tinyauth/internal/repository"
	"github.com/steveiliop56/tinyauth/internal/service"
	"github.com/steveiliop56/tinyauth/internal/utils/tlog"
	"gotest.tools/v3/assert"
)

var oidcServiceConfig = service.OIDCServiceConfig{
	Clients: map[string]config.OIDCClientConfig{
		"client1": {
			ClientID:         "some-client-id",
			ClientSecret:     "some-client-secret",
			ClientSecretFile: "",
			TrustedRedirectURIs: []string{
				"https://example.com/oauth/callback",
			},
			Name: "Client 1",
		},
	},
	PrivateKeyPath: "/tmp/tinyauth_oidc_key",
	PublicKeyPath:  "/tmp/tinyauth_oidc_key.pub",
	Issuer:         "https://example.com",
	SessionExpiry:  3600,
}

var oidcCtrlTestContext = config.UserContext{
	Username:    "test",
	Name:        "Test",
	Email:       "test@example.com",
	IsLoggedIn:  true,
	IsBasicAuth: false,
	OAuth:       false,
	Provider:    "ldap", // ldap in order to test the groups
	TotpPending: false,
	OAuthGroups: "",
	TotpEnabled: false,
	OAuthName:   "",
	OAuthSub:    "",
	LdapGroups:  "test1,test2",
}

// Test is not amazing, but it will confirm the OIDC server works
func TestOIDCController(t *testing.T) {
	tlog.NewSimpleLogger().Init()

	// Create an app instance
	app := bootstrap.NewBootstrapApp(config.Config{})

	// Get db
	db, err := app.SetupDatabase("/tmp/tinyauth.db")
	assert.NilError(t, err)

	// Create queries
	queries := repository.New(db)

	// Create a new OIDC Servicee
	oidcService := service.NewOIDCService(oidcServiceConfig, queries)
	err = oidcService.Init()
	assert.NilError(t, err)

	// Create test router
	gin.SetMode(gin.TestMode)
	router := gin.Default()

	router.Use(func(c *gin.Context) {
		c.Set("context", &oidcCtrlTestContext)
		c.Next()
	})

	group := router.Group("/api")

	// Register oidc controller
	oidcController := controller.NewOIDCController(controller.OIDCControllerConfig{}, oidcService, group)
	oidcController.SetupRoutes()

	// Get redirect URL test
	recorder := httptest.NewRecorder()

	marshalled, err := json.Marshal(service.AuthorizeRequest{
		Scope:        "openid profile email groups",
		ResponseType: "code",
		ClientID:     "some-client-id",
		RedirectURI:  "https://example.com/oauth/callback",
		State:        "some-state",
	})

	assert.NilError(t, err)

	req, err := http.NewRequest("POST", "/api/oidc/authorize", strings.NewReader(string(marshalled)))
	assert.NilError(t, err)

	router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	resJson := map[string]any{}

	err = json.Unmarshal(recorder.Body.Bytes(), &resJson)
	assert.NilError(t, err)

	redirect_uri, ok := resJson["redirect_uri"].(string)
	assert.Assert(t, ok)

	u, err := url.Parse(redirect_uri)
	assert.NilError(t, err)

	m, err := url.ParseQuery(u.RawQuery)
	assert.NilError(t, err)
	assert.Equal(t, m["state"][0], "some-state")

	code := m["code"][0]

	// Exchange code for token
	recorder = httptest.NewRecorder()

	params, err := query.Values(controller.TokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "https://example.com/oauth/callback",
	})

	assert.NilError(t, err)

	req, err = http.NewRequest("POST", "/api/oidc/token", strings.NewReader(params.Encode()))

	assert.NilError(t, err)

	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("some-client-id", "some-client-secret")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	resJson = map[string]any{}

	err = json.Unmarshal(recorder.Body.Bytes(), &resJson)
	assert.NilError(t, err)

	accessToken, ok := resJson["access_token"].(string)
	assert.Assert(t, ok)

	_, ok = resJson["id_token"].(string)
	assert.Assert(t, ok)

	refreshToken, ok := resJson["refresh_token"].(string)
	assert.Assert(t, ok)

	expires_in, ok := resJson["expires_in"].(float64)
	assert.Assert(t, ok)
	assert.Equal(t, expires_in, float64(oidcServiceConfig.SessionExpiry))

	// Ensure code is expired
	recorder = httptest.NewRecorder()

	params, err = query.Values(controller.TokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "https://example.com/oauth/callback",
	})

	assert.NilError(t, err)

	req, err = http.NewRequest("POST", "/api/oidc/token", strings.NewReader(params.Encode()))

	assert.NilError(t, err)

	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("some-client-id", "some-client-secret")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusBadRequest, recorder.Code)

	// Test userinfo
	recorder = httptest.NewRecorder()

	req, err = http.NewRequest("GET", "/api/oidc/userinfo", nil)
	assert.NilError(t, err)

	req.Header.Set("authorization", fmt.Sprintf("Bearer %s", accessToken))

	router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	resJson = map[string]any{}

	err = json.Unmarshal(recorder.Body.Bytes(), &resJson)
	assert.NilError(t, err)

	_, ok = resJson["sub"].(string)
	assert.Assert(t, ok)

	name, ok := resJson["name"].(string)
	assert.Assert(t, ok)
	assert.Equal(t, name, oidcCtrlTestContext.Name)

	email, ok := resJson["email"].(string)
	assert.Assert(t, ok)
	assert.Equal(t, email, oidcCtrlTestContext.Email)

	preferred_username, ok := resJson["preferred_username"].(string)
	assert.Assert(t, ok)
	assert.Equal(t, preferred_username, oidcCtrlTestContext.Username)

	// Not sure why this is failing, will look into it later
	igroups, ok := resJson["groups"].([]any)
	assert.Assert(t, ok)

	groups := make([]string, len(igroups))
	for i, group := range igroups {
		groups[i], ok = group.(string)
		assert.Assert(t, ok)
	}

	assert.DeepEqual(t, strings.Split(oidcCtrlTestContext.LdapGroups, ","), groups)

	// Test refresh token
	recorder = httptest.NewRecorder()

	params, err = query.Values(controller.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: refreshToken,
	})

	assert.NilError(t, err)

	req, err = http.NewRequest("POST", "/api/oidc/token", strings.NewReader(params.Encode()))

	assert.NilError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("some-client-id", "some-client-secret")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	resJson = map[string]any{}

	err = json.Unmarshal(recorder.Body.Bytes(), &resJson)

	assert.NilError(t, err)

	newToken, ok := resJson["access_token"].(string)
	assert.Assert(t, ok)
	assert.Assert(t, newToken != accessToken)

	// Ensure old token is invalid
	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/api/oidc/userinfo", nil)

	assert.NilError(t, err)

	req.Header.Set("authorization", fmt.Sprintf("Bearer %s", accessToken))

	router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	// Test new token
	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/api/oidc/userinfo", nil)

	assert.NilError(t, err)

	req.Header.Set("authorization", fmt.Sprintf("Bearer %s", newToken))

	router.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
}
