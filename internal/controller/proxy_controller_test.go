package controller_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/steveiliop56/tinyauth/internal/bootstrap"
	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/controller"
	"github.com/steveiliop56/tinyauth/internal/repository"
	"github.com/steveiliop56/tinyauth/internal/service"

	"github.com/gin-gonic/gin"
	"gotest.tools/v3/assert"
)

var loggedInCtx = config.UserContext{
	Username:   "test",
	Name:       "Test",
	Email:      "test@example.com",
	IsLoggedIn: true,
	Provider:   "local",
}

func setupProxyController(t *testing.T, middlewares []gin.HandlerFunc) (*gin.Engine, *httptest.ResponseRecorder) {
	// Setup
	gin.SetMode(gin.TestMode)
	router := gin.Default()

	if len(middlewares) > 0 {
		for _, m := range middlewares {
			router.Use(m)
		}
	}

	group := router.Group("/api")
	recorder := httptest.NewRecorder()

	// Mock app
	app := bootstrap.NewBootstrapApp(config.Config{})

	// Database
	db, err := app.SetupDatabase(":memory:")

	assert.NilError(t, err)

	// Queries
	queries := repository.New(db)

	// Docker
	dockerService := service.NewDockerService()

	assert.NilError(t, dockerService.Init())

	// Access controls
	accessControlsService := service.NewAccessControlsService(dockerService, map[string]config.App{
		"whoami": {
			Path: config.AppPath{
				Allow: "/allow",
			},
		},
	})

	assert.NilError(t, accessControlsService.Init())

	// Auth service
	authService := service.NewAuthService(service.AuthServiceConfig{
		Users: []config.User{
			{
				Username: "testuser",
				Password: "$2a$10$ne6z693sTgzT3ePoQ05PgOecUHnBjM7sSNj6M.l5CLUP.f6NyCnt.", // test
			},
			{
				Username:   "totpuser",
				Password:   "$2a$10$ne6z693sTgzT3ePoQ05PgOecUHnBjM7sSNj6M.l5CLUP.f6NyCnt.",
				TotpSecret: "foo",
			},
		},
		OauthWhitelist:     []string{},
		SessionExpiry:      3600,
		SessionMaxLifetime: 0,
		SecureCookie:       false,
		CookieDomain:       "localhost",
		LoginTimeout:       300,
		LoginMaxRetries:    3,
		SessionCookieName:  "tinyauth-session",
	}, dockerService, nil, queries)

	// Controller
	ctrl := controller.NewProxyController(controller.ProxyControllerConfig{
		AppURL: "http://tinyauth.example.com",
	}, group, accessControlsService, authService)
	ctrl.SetupRoutes()

	return router, recorder
}

// TODO: Needs tests for context middleware

func TestProxyHandler(t *testing.T) {
	// Test logged out user traefik/caddy (forward_auth)
	router, recorder := setupProxyController(t, nil)

	req, err := http.NewRequest("GET", "/api/auth/traefik", nil)
	assert.NilError(t, err)

	req.Header.Set("x-forwarded-host", "whoami.example.com")
	req.Header.Set("x-forwarded-proto", "http")
	req.Header.Set("x-forwarded-uri", "/")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusUnauthorized)

	// Test logged out user nginx (auth_request)
	router, recorder = setupProxyController(t, nil)

	req, err = http.NewRequest("GET", "/api/auth/nginx", nil)
	assert.NilError(t, err)

	req.Header.Set("x-original-url", "http://whoami.example.com/")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusUnauthorized)

	// Test logged out user envoy (ext_authz)
	router, recorder = setupProxyController(t, nil)

	req, err = http.NewRequest("GET", "/api/auth/envoy?path=/", nil)
	assert.NilError(t, err)

	req.Host = "whoami.example.com"
	req.Header.Set("x-forwarded-proto", "http")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusUnauthorized)

	// Test logged in user traefik/caddy (forward_auth)
	router, recorder = setupProxyController(t, []gin.HandlerFunc{
		func(c *gin.Context) {
			c.Set("context", &loggedInCtx)
			c.Next()
		},
	})

	req, err = http.NewRequest("GET", "/api/auth/traefik", nil)
	assert.NilError(t, err)

	req.Header.Set("x-forwarded-host", "whoami.example.com")
	req.Header.Set("x-forwarded-proto", "http")
	req.Header.Set("x-forwarded-uri", "/")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Test logged in user nginx (auth_request)
	router, recorder = setupProxyController(t, []gin.HandlerFunc{
		func(c *gin.Context) {
			c.Set("context", &loggedInCtx)
			c.Next()
		},
	})

	req, err = http.NewRequest("GET", "/api/auth/nginx", nil)
	assert.NilError(t, err)

	req.Header.Set("x-original-url", "http://whoami.example.com/")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Test logged in user envoy (ext_authz)
	router, recorder = setupProxyController(t, []gin.HandlerFunc{
		func(c *gin.Context) {
			c.Set("context", &loggedInCtx)
			c.Next()
		},
	})

	req, err = http.NewRequest("GET", "/api/auth/envoy?path=/", nil)
	assert.NilError(t, err)

	req.Host = "whoami.example.com"
	req.Header.Set("x-forwarded-proto", "http")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Test ACL allow caddy/traefik (forward_auth)
	router, recorder = setupProxyController(t, nil)

	req, err = http.NewRequest("GET", "/api/auth/traefik", nil)
	assert.NilError(t, err)

	req.Header.Set("x-forwarded-host", "whoami.example.com")
	req.Header.Set("x-forwarded-proto", "http")
	req.Header.Set("x-forwarded-uri", "/allow")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Test ACL allow nginx
	router, recorder = setupProxyController(t, nil)

	req, err = http.NewRequest("GET", "/api/auth/nginx", nil)
	assert.NilError(t, err)

	req.Header.Set("x-original-url", "http://whoami.example.com/allow")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Test ACL allow envoy
	router, recorder = setupProxyController(t, nil)

	req, err = http.NewRequest("GET", "/api/auth/envoy?path=/allow", nil)
	assert.NilError(t, err)

	req.Host = "whoami.example.com"
	req.Header.Set("x-forwarded-proto", "http")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Test traefik/caddy (forward_auth) without required headers
	router, recorder = setupProxyController(t, nil)

	req, err = http.NewRequest("GET", "/api/auth/traefik", nil)
	assert.NilError(t, err)

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusBadRequest)

	// Test nginx (forward_auth) without required headers
	router, recorder = setupProxyController(t, nil)

	req, err = http.NewRequest("GET", "/api/auth/nginx", nil)
	assert.NilError(t, err)

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusBadRequest)

	// Test envoy (forward_auth) without required headers
	router, recorder = setupProxyController(t, nil)

	req, err = http.NewRequest("GET", "/api/auth/envoy", nil)
	assert.NilError(t, err)

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusBadRequest)

	// Test nginx (auth_request) with forward_auth fallback with ACLs
	router, recorder = setupProxyController(t, nil)

	req, err = http.NewRequest("GET", "/api/auth/nginx", nil)
	assert.NilError(t, err)

	req.Header.Set("x-forwarded-host", "whoami.example.com")
	req.Header.Set("x-forwarded-proto", "http")
	req.Header.Set("x-forwarded-uri", "/allow")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Test envoy (ext_authz) with forward_auth fallback with ACLs
	router, recorder = setupProxyController(t, nil)

	req, err = http.NewRequest("GET", "/api/auth/envoy", nil)
	assert.NilError(t, err)

	req.Header.Set("x-forwarded-host", "whoami.example.com")
	req.Header.Set("x-forwarded-proto", "http")
	req.Header.Set("x-forwarded-uri", "/allow")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)

	// Test envoy (ext_authz) with empty path
	router, recorder = setupProxyController(t, nil)

	req, err = http.NewRequest("GET", "/api/auth/envoy", nil)
	assert.NilError(t, err)

	req.Host = "whoami.example.com"
	req.Header.Set("x-forwarded-proto", "http")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusUnauthorized)

	// Ensure forward_auth fallback works with path (should ignore)
	router, recorder = setupProxyController(t, nil)

	req, err = http.NewRequest("GET", "/api/auth/traefik?path=/allow", nil)
	assert.NilError(t, err)

	req.Header.Set("x-forwarded-proto", "http")
	req.Header.Set("x-forwarded-host", "whoami.example.com")
	req.Header.Set("x-forwarded-uri", "/allow")

	router.ServeHTTP(recorder, req)
	assert.Equal(t, recorder.Code, http.StatusOK)
}
