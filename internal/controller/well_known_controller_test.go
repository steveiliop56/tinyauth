package controller_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/steveiliop56/tinyauth/internal/bootstrap"
	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/controller"
	"github.com/steveiliop56/tinyauth/internal/repository"
	"github.com/steveiliop56/tinyauth/internal/service"
	"github.com/stretchr/testify/assert"
)

func TestWellKnownController(t *testing.T) {
	oidcServiceCfg := service.OIDCServiceConfig{
		Clients: map[string]config.OIDCClientConfig{
			"test": {
				ClientID:            "some-client-id",
				ClientSecret:        "some-client-secret",
				TrustedRedirectURIs: []string{"https://test.example.com/callback"},
				Name:                "Test Client",
			},
		},
		PrivateKeyPath: "/tmp/tinyauth_testing_key.pem",
		PublicKeyPath:  "/tmp/tinyauth_testing_key.pub",
		Issuer:         "https://tinyauth.example.com",
		SessionExpiry:  500,
	}

	type testCase struct {
		description string
		run         func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder)
	}

	tests := []testCase{
		{
			description: "Ensure well-known endpoint returns correct OIDC configuration",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)

				res := controller.OpenIDConnectConfiguration{}
				err := json.Unmarshal(recorder.Body.Bytes(), &res)
				assert.NoError(t, err)

				expected := controller.OpenIDConnectConfiguration{
					Issuer:                            oidcServiceCfg.Issuer,
					AuthorizationEndpoint:             fmt.Sprintf("%s/authorize", oidcServiceCfg.Issuer),
					TokenEndpoint:                     fmt.Sprintf("%s/api/oidc/token", oidcServiceCfg.Issuer),
					UserinfoEndpoint:                  fmt.Sprintf("%s/api/oidc/userinfo", oidcServiceCfg.Issuer),
					JwksUri:                           fmt.Sprintf("%s/.well-known/jwks.json", oidcServiceCfg.Issuer),
					ScopesSupported:                   service.SupportedScopes,
					ResponseTypesSupported:            service.SupportedResponseTypes,
					GrantTypesSupported:               service.SupportedGrantTypes,
					SubjectTypesSupported:             []string{"pairwise"},
					IDTokenSigningAlgValuesSupported:  []string{"RS256"},
					TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
					ClaimsSupported:                   []string{"sub", "updated_at", "name", "preferred_username", "email", "email_verified", "groups"},
					ServiceDocumentation:              "https://tinyauth.app/docs/guides/oidc",
				}

				assert.Equal(t, res, expected)
			},
		},
		{
			description: "Ensure well-known endpoint returns correct JWKS",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)

				decodedBody := make(map[string]any)
				err := json.Unmarshal(recorder.Body.Bytes(), &decodedBody)
				assert.NoError(t, err)

				keys, ok := decodedBody["keys"].([]any)
				assert.True(t, ok)
				assert.Len(t, keys, 1)

				keyData, ok := keys[0].(map[string]any)
				assert.True(t, ok)
				assert.Equal(t, "RSA", keyData["kty"])
				assert.Equal(t, "sig", keyData["use"])
				assert.Equal(t, "RS256", keyData["alg"])
			},
		},
	}

	app := bootstrap.NewBootstrapApp(config.Config{})

	db, err := app.SetupDatabase("/tmp/tinyauth_test.db")
	assert.NoError(t, err)

	queries := repository.New(db)

	oidcService := service.NewOIDCService(oidcServiceCfg, queries)
	err = oidcService.Init()
	assert.NoError(t, err)

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()
			gin.SetMode(gin.TestMode)

			recorder := httptest.NewRecorder()

			wellKnownController := controller.NewWellKnownController(controller.WellKnownControllerConfig{}, oidcService, router)
			wellKnownController.SetupRoutes()

			test.run(t, router, recorder)
		})
	}

	err = db.Close()
	assert.NoError(t, err)

	err = os.Remove("/tmp/tinyauth_test.db")
	assert.NoError(t, err)
}
