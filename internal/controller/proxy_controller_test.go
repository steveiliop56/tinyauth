package controller_test

import (
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

func setupProxyController(t *testing.T, middlewares *[]gin.HandlerFunc) (*gin.Engine, *httptest.ResponseRecorder, *service.AuthService) {
	// Setup
	gin.SetMode(gin.TestMode)
	router := gin.Default()

	if middlewares != nil {
		for _, m := range *middlewares {
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
	accessControlsService := service.NewAccessControlsService(dockerService, map[string]config.App{})

	assert.NilError(t, accessControlsService.Init())

	// Auth service
	authService := service.NewAuthService(service.AuthServiceConfig{
		Users: []config.User{
			{
				Username: "testuser",
				Password: "$2a$10$ne6z693sTgzT3ePoQ05PgOecUHnBjM7sSNj6M.l5CLUP.f6NyCnt.", // test
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
		AppURL: "http://localhost:8080",
	}, group, accessControlsService, authService)
	ctrl.SetupRoutes()

	return router, recorder, authService
}

func TestProxyHandler(t *testing.T) {
	// Setup
	router, recorder, authService := setupProxyController(t, nil)

	// Test invalid proxy
	req := httptest.NewRequest("GET", "/api/auth/invalidproxy", nil)
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 400, recorder.Code)

	// Test invalid method for non-envoy proxy
	recorder = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/auth/traefik", nil)
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 405, recorder.Code)
	assert.Equal(t, "GET", recorder.Header().Get("Allow"))

	// Test logged out user (traefik/caddy)
	recorder = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/auth/traefik", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")
	req.Header.Set("X-Forwarded-Uri", "/somepath")
	req.Header.Set("Accept", "text/html")
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 307, recorder.Code)
	assert.Equal(t, "http://localhost:8080/login?redirect_uri=https%3A%2F%2Fexample.com%2Fsomepath", recorder.Header().Get("Location"))

	// Test logged out user (envoy - POST method)
	recorder = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/api/auth/envoy", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")
	req.Header.Set("X-Forwarded-Uri", "/somepath")
	req.Header.Set("Accept", "text/html")
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 307, recorder.Code)
	assert.Equal(t, "http://localhost:8080/login?redirect_uri=https%3A%2F%2Fexample.com%2Fsomepath", recorder.Header().Get("Location"))

	// Test logged out user (envoy - DELETE method)
	recorder = httptest.NewRecorder()
	req = httptest.NewRequest("DELETE", "/api/auth/envoy", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")
	req.Header.Set("X-Forwarded-Uri", "/somepath")
	req.Header.Set("Accept", "text/html")
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 307, recorder.Code)
	assert.Equal(t, "http://localhost:8080/login?redirect_uri=https%3A%2F%2Fexample.com%2Fsomepath", recorder.Header().Get("Location"))

	// Test logged out user (nginx)
	recorder = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/auth/nginx", nil)
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 401, recorder.Code)

	// Test logged in user
	c := gin.CreateTestContextOnly(recorder, router)

	err := authService.CreateSessionCookie(c, &repository.Session{
		Username:    "testuser",
		Name:        "testuser",
		Email:       "testuser@example.com",
		Provider:    "username",
		TotpPending: false,
		OAuthGroups: "",
	})

	assert.NilError(t, err)

	cookie := c.Writer.Header().Get("Set-Cookie")

	router, recorder, _ = setupProxyController(t, &[]gin.HandlerFunc{
		func(c *gin.Context) {
			c.Set("context", &config.UserContext{
				Username:    "testuser",
				Name:        "testuser",
				Email:       "testuser@example.com",
				IsLoggedIn:  true,
				OAuth:       false,
				Provider:    "username",
				TotpPending: false,
				OAuthGroups: "",
				TotpEnabled: false,
			})
			c.Next()
		},
	})

	req = httptest.NewRequest("GET", "/api/auth/traefik", nil)
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Accept", "text/html")
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 200, recorder.Code)

	assert.Equal(t, "testuser", recorder.Header().Get("Remote-User"))
	assert.Equal(t, "testuser", recorder.Header().Get("Remote-Name"))
	assert.Equal(t, "testuser@example.com", recorder.Header().Get("Remote-Email"))

	// Ensure basic auth is disabled for TOTP enabled users
	router, recorder, _ = setupProxyController(t, &[]gin.HandlerFunc{
		func(c *gin.Context) {
			c.Set("context", &config.UserContext{
				Username:    "testuser",
				Name:        "testuser",
				Email:       "testuser@example.com",
				IsLoggedIn:  true,
				OAuth:       false,
				Provider:    "basic",
				TotpPending: false,
				OAuthGroups: "",
				TotpEnabled: true,
			})
			c.Next()
		},
	})

	req = httptest.NewRequest("GET", "/api/auth/traefik", nil)
	req.SetBasicAuth("testuser", "test")
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 401, recorder.Code)
}
