package controller

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/steveiliop56/tinyauth/internal/service"
)

type OpenIDConnectConfiguration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksUri                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	ServiceDocumentation              string   `json:"service_documentation"`
}

type WellKnownControllerConfig struct {
	OpenIDConnectIssuer string
}

type WellKnownController struct {
	config WellKnownControllerConfig
	engine *gin.Engine
}

func NewWellKnownController(config WellKnownControllerConfig, engine *gin.Engine) *WellKnownController {
	return &WellKnownController{
		config: config,
		engine: engine,
	}
}

func (controller *WellKnownController) SetupRoutes() {
	controller.engine.GET("/.well-known/openid-configuration", controller.OpenIDConnectConfiguration)
}

func (controller *WellKnownController) OpenIDConnectConfiguration(c *gin.Context) {
	c.JSON(200, OpenIDConnectConfiguration{
		Issuer:                            controller.config.OpenIDConnectIssuer,
		AuthorizationEndpoint:             fmt.Sprintf("%s/authorize", controller.config.OpenIDConnectIssuer),
		TokenEndpoint:                     fmt.Sprintf("%s/api/oidc/token", controller.config.OpenIDConnectIssuer),
		UserinfoEndpoint:                  fmt.Sprintf("%s/api/oidc/userinfo", controller.config.OpenIDConnectIssuer),
		JwksUri:                           fmt.Sprintf("%s/api/oidc/jwks", controller.config.OpenIDConnectIssuer),
		ScopesSupported:                   service.SupportedScopes,
		ResponseTypesSupported:            service.SupportedResponseTypes,
		GrantTypesSupported:               service.SupportedGrantTypes,
		SubjectTypesSupported:             []string{"pairwise"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		ClaimsSupported:                   []string{"sub", "updated_at", "name", "preferred_username", "email", "groups"},
		ServiceDocumentation:              "https://tinyauth.app/docs/reference/openid",
	})
}
