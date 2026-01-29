package controller

import (
	"fmt"
	"net/http"

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

type WellKnownControllerConfig struct{}

type WellKnownController struct {
	config WellKnownControllerConfig
	engine *gin.Engine
	oidc   *service.OIDCService
}

func NewWellKnownController(config WellKnownControllerConfig, oidc *service.OIDCService, engine *gin.Engine) *WellKnownController {
	return &WellKnownController{
		config: config,
		oidc:   oidc,
		engine: engine,
	}
}

func (controller *WellKnownController) SetupRoutes() {
	controller.engine.GET("/.well-known/openid-configuration", controller.OpenIDConnectConfiguration)
	controller.engine.GET("/.well-known/jwks.json", controller.JWKS)
}

func (controller *WellKnownController) OpenIDConnectConfiguration(c *gin.Context) {
	issuer := controller.oidc.GetIssuer()
	c.JSON(200, OpenIDConnectConfiguration{
		Issuer:                            issuer,
		AuthorizationEndpoint:             fmt.Sprintf("%s/authorize", issuer),
		TokenEndpoint:                     fmt.Sprintf("%s/api/oidc/token", issuer),
		UserinfoEndpoint:                  fmt.Sprintf("%s/api/oidc/userinfo", issuer),
		JwksUri:                           fmt.Sprintf("%s/.well-known/jwks.json", issuer),
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

func (controller *WellKnownController) JWKS(c *gin.Context) {
	jwks, err := controller.oidc.GetJWK()

	if err != nil {
		c.JSON(500, gin.H{
			"status":  "500",
			"message": "failed to get JWK",
		})
		return
	}

	c.Header("content-type", "application/json")

	c.Writer.WriteString(`{"keys":[`)
	c.Writer.Write(jwks)
	c.Writer.WriteString(`]}`)

	c.Status(http.StatusOK)
}
