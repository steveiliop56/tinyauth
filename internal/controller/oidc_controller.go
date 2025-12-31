package controller

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/service"
	"github.com/steveiliop56/tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

// OIDCControllerConfig holds configuration for the OIDC controller.
type OIDCControllerConfig struct {
	AppURL       string // Base URL of the application
	CookieDomain string // Domain for setting cookies
}

// OIDCController handles OpenID Connect (OIDC) protocol endpoints.
// It implements the OIDC provider functionality including discovery, authorization,
// token exchange, userinfo, and JWKS endpoints.
type OIDCController struct {
	config OIDCControllerConfig
	router *gin.RouterGroup
	oidc   *service.OIDCService
	auth   *service.AuthService
}

// NewOIDCController creates a new OIDC controller with the given configuration and services.
func NewOIDCController(config OIDCControllerConfig, router *gin.RouterGroup, oidc *service.OIDCService, auth *service.AuthService) *OIDCController {
	return &OIDCController{
		config: config,
		router: router,
		oidc:   oidc,
		auth:   auth,
	}
}

// SetupRoutes registers all OIDC endpoints with the router.
// This includes:
//   - /.well-known/openid-configuration - OIDC discovery endpoint
//   - /oidc/authorize - Authorization endpoint
//   - /oidc/token - Token endpoint
//   - /oidc/userinfo - UserInfo endpoint
//   - /oidc/jwks - JSON Web Key Set endpoint
func (controller *OIDCController) SetupRoutes() {
	// Well-known discovery endpoint
	controller.router.GET("/.well-known/openid-configuration", controller.discoveryHandler)

	// OIDC endpoints
	oidcGroup := controller.router.Group("/oidc")
	oidcGroup.GET("/authorize", controller.authorizeHandler)
	oidcGroup.POST("/token", controller.tokenHandler)
	oidcGroup.GET("/userinfo", controller.userinfoHandler)
	oidcGroup.GET("/jwks", controller.jwksHandler)
}

// discoveryHandler handles the OIDC discovery endpoint.
// Returns the OpenID Connect discovery document as specified in RFC 8414.
// The document contains metadata about the OIDC provider including endpoints,
// supported features, and cryptographic capabilities.
func (controller *OIDCController) discoveryHandler(c *gin.Context) {
	issuer := controller.oidc.GetIssuer()
	baseURL := strings.TrimSuffix(controller.config.AppURL, "/")

	discovery := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                fmt.Sprintf("%s/api/oidc/authorize", baseURL),
		"token_endpoint":                        fmt.Sprintf("%s/api/oidc/token", baseURL),
		"userinfo_endpoint":                     fmt.Sprintf("%s/api/oidc/userinfo", baseURL),
		"jwks_uri":                              fmt.Sprintf("%s/api/oidc/jwks", baseURL),
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
	}

	c.JSON(http.StatusOK, discovery)
}

// authorizeHandler handles the OIDC authorization endpoint.
// Implements the authorization code flow as specified in OAuth 2.0 RFC 6749.
// Validates client credentials, redirect URI, scopes, and response type.
// Supports PKCE (RFC 7636) for enhanced security.
// If the user is not authenticated, redirects to the login page with the
// authorization request parameters preserved for redirect after login.
// On success, generates an authorization code and redirects to the client's
// redirect URI with the code and state parameter.
func (controller *OIDCController) authorizeHandler(c *gin.Context) {
	// Get query parameters
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")
	nonce := c.Query("nonce")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")

	// Validate required parameters
	// Return JSON error instead of redirecting since redirect_uri is not yet validated
	if clientID == "" || redirectURI == "" || responseType == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
		return
	}

	// Get client
	// Return JSON error instead of redirecting since redirect_uri is not yet validated
	client, err := controller.oidc.GetClient(clientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "Client not found",
		})
		return
	}

	// Validate redirect URI
	// After this point, redirect_uri is validated and we can safely redirect
	if !controller.oidc.ValidateRedirectURI(client, redirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid redirect_uri",
		})
		return
	}

	// Validate response type
	if !controller.oidc.ValidateResponseType(client, responseType) {
		controller.redirectError(c, redirectURI, state, "unsupported_response_type", "Unsupported response_type")
		return
	}

	// Validate scopes
	scopes, err := controller.oidc.ValidateScope(client, scope)
	if err != nil {
		controller.redirectError(c, redirectURI, state, "invalid_scope", "Invalid scope")
		return
	}

	// Check if user is authenticated
	userContext, err := utils.GetContext(c)
	if err != nil || !userContext.IsLoggedIn {
		// User not authenticated, redirect to login
		// Build the full authorize URL to redirect back to after login
		authorizeURL := fmt.Sprintf("%s%s", controller.config.AppURL, c.Request.URL.Path)
		if c.Request.URL.RawQuery != "" {
			authorizeURL = fmt.Sprintf("%s?%s", authorizeURL, c.Request.URL.RawQuery)
		}
		loginURL := fmt.Sprintf("%s/login?redirect_uri=%s&client_id=%s&response_type=%s&scope=%s&state=%s&nonce=%s&code_challenge=%s&code_challenge_method=%s",
			controller.config.AppURL,
			url.QueryEscape(authorizeURL),
			url.QueryEscape(clientID),
			url.QueryEscape(responseType),
			url.QueryEscape(scope),
			url.QueryEscape(state),
			url.QueryEscape(nonce),
			url.QueryEscape(codeChallenge),
			url.QueryEscape(codeChallengeMethod))
		c.Redirect(http.StatusFound, loginURL)
		return
	}

	// Check for TOTP pending
	if userContext.TotpPending {
		controller.redirectError(c, redirectURI, state, "access_denied", "TOTP verification required")
		return
	}

	// Generate authorization code (including PKCE challenge if provided)
	authCode, err := controller.oidc.GenerateAuthorizationCode(&userContext, clientID, redirectURI, scopes, nonce, codeChallenge, codeChallengeMethod)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate authorization code")
		controller.redirectError(c, redirectURI, state, "server_error", "Internal server error")
		return
	}

	// Build redirect URL with authorization code
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		controller.redirectError(c, redirectURI, state, "invalid_request", "Invalid redirect_uri")
		return
	}

	query := redirectURL.Query()
	query.Set("code", authCode)
	if state != "" {
		query.Set("state", state)
	}
	redirectURL.RawQuery = query.Encode()

	c.Redirect(http.StatusFound, redirectURL.String())
}

// tokenHandler handles the OIDC token endpoint.
// Exchanges an authorization code for access and ID tokens.
// Validates the authorization code, client credentials, redirect URI, and PKCE verifier.
// Returns an access token and optionally an ID token (if openid scope is present).
// Implements the authorization code grant type as specified in OAuth 2.0 RFC 6749.
func (controller *OIDCController) tokenHandler(c *gin.Context) {
	// Get grant type
	grantType := c.PostForm("grant_type")
	if grantType == "" {
		grantType = c.Query("grant_type")
	}

	if grantType != "authorization_code" {
		controller.tokenError(c, "unsupported_grant_type", "Only authorization_code grant type is supported")
		return
	}

	// Get authorization code
	code := c.PostForm("code")
	if code == "" {
		code = c.Query("code")
	}

	if code == "" {
		controller.tokenError(c, "invalid_request", "Missing authorization code")
		return
	}

	// Get client credentials
	clientID, clientSecret, err := controller.getClientCredentials(c)
	if err != nil {
		controller.tokenError(c, "invalid_client", "Invalid client credentials")
		return
	}

	// Get client
	client, err := controller.oidc.GetClient(clientID)
	if err != nil {
		controller.tokenError(c, "invalid_client", "Client not found")
		return
	}

	// Verify client secret
	if !controller.oidc.VerifyClientSecret(client, clientSecret) {
		controller.tokenError(c, "invalid_client", "Invalid client secret")
		return
	}

	// Get redirect URI
	redirectURI := c.PostForm("redirect_uri")
	if redirectURI == "" {
		redirectURI = c.Query("redirect_uri")
	}

	// Validate redirect URI
	if !controller.oidc.ValidateRedirectURI(client, redirectURI) {
		controller.tokenError(c, "invalid_request", "Invalid redirect_uri")
		return
	}

	// Get code_verifier for PKCE validation
	codeVerifier := c.PostForm("code_verifier")
	if codeVerifier == "" {
		codeVerifier = c.Query("code_verifier")
	}

	// Validate authorization code
	userContext, scopes, nonce, codeChallenge, codeChallengeMethod, err := controller.oidc.ValidateAuthorizationCode(code, clientID, redirectURI)
	if err != nil {
		log.Error().Err(err).Msg("Failed to validate authorization code")
		controller.tokenError(c, "invalid_grant", "Invalid or expired authorization code")
		return
	}

	// Validate PKCE if code challenge was provided
	if codeChallenge != "" {
		if err := controller.oidc.ValidatePKCE(codeChallenge, codeChallengeMethod, codeVerifier); err != nil {
			log.Error().Err(err).Msg("PKCE validation failed")
			controller.tokenError(c, "invalid_grant", "Invalid code_verifier")
			return
		}
	}

	// Generate tokens
	accessToken, err := controller.oidc.GenerateAccessToken(userContext, clientID, scopes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate access token")
		controller.tokenError(c, "server_error", "Internal server error")
		return
	}

	// Generate ID token if openid scope is present
	var idToken string
	hasOpenID := false
	for _, scope := range scopes {
		if scope == "openid" {
			hasOpenID = true
			break
		}
	}

	if hasOpenID {
		idToken, err = controller.oidc.GenerateIDToken(userContext, clientID, nonce)
		if err != nil {
			log.Error().Err(err).Msg("Failed to generate ID token")
			controller.tokenError(c, "server_error", "Internal server error")
			return
		}
	}

	// Return token response
	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   controller.oidc.GetAccessTokenExpiry(),
		"scope":        strings.Join(scopes, " "),
	}

	if idToken != "" {
		response["id_token"] = idToken
	}

	c.JSON(http.StatusOK, response)
}

// userinfoHandler handles the OIDC UserInfo endpoint.
// Returns user information claims for the authenticated user based on the
// provided access token. Validates the access token signature, issuer, and expiration.
// Returns standard OIDC claims: sub, email, name, and preferred_username.
func (controller *OIDCController) userinfoHandler(c *gin.Context) {
	// Get access token from Authorization header or query parameter
	accessToken := controller.getAccessToken(c)
	if accessToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "Missing access token",
		})
		return
	}

	// Get optional client_id from request for audience validation
	clientID := c.Query("client_id")
	if clientID == "" {
		clientID = c.PostForm("client_id")
	}

	// Validate and parse access token with audience validation
	userContext, err := controller.oidc.ValidateAccessTokenForClient(accessToken, clientID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to validate access token")
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "Invalid or expired access token",
		})
		return
	}

	// Return user info
	userInfo := map[string]interface{}{
		"sub":                userContext.Username,
		"email":              userContext.Email,
		"name":               userContext.Name,
		"preferred_username": userContext.Username,
	}

	c.JSON(http.StatusOK, userInfo)
}

// jwksHandler handles the JSON Web Key Set (JWKS) endpoint.
// Returns the public keys used to verify ID tokens and access tokens.
// The keys are in JWK format as specified in RFC 7517.
func (controller *OIDCController) jwksHandler(c *gin.Context) {
	jwks, err := controller.oidc.GetJWKS()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get JWKS")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
		})
		return
	}

	c.JSON(http.StatusOK, jwks)
}

// Helper functions

// redirectError redirects the user to the redirect URI with an error response.
// Includes the error code, error description, and state parameter (if provided).
// If the redirect URI is invalid or empty, returns a JSON error response instead.
func (controller *OIDCController) redirectError(c *gin.Context, redirectURI string, state string, errorCode string, errorDescription string) {
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             errorCode,
			"error_description": errorDescription,
		})
		return
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             errorCode,
			"error_description": errorDescription,
		})
		return
	}

	query := redirectURL.Query()
	query.Set("error", errorCode)
	query.Set("error_description", errorDescription)
	if state != "" {
		query.Set("state", state)
	}
	redirectURL.RawQuery = query.Encode()

	c.Redirect(http.StatusFound, redirectURL.String())
}

// tokenError returns a JSON error response for token endpoint errors.
// Uses the standard OAuth 2.0 error format with error and error_description fields.
func (controller *OIDCController) tokenError(c *gin.Context, errorCode string, errorDescription string) {
	c.JSON(http.StatusBadRequest, gin.H{
		"error":             errorCode,
		"error_description": errorDescription,
	})
}

// getClientCredentials extracts client credentials from the request.
// Supports client_secret_basic (HTTP Basic Authentication) and
// client_secret_post (POST form parameters) as specified in the discovery document.
// Does not accept credentials via query parameters for security reasons
// (they may be logged in access logs, browser history, or referrer headers).
// Returns the client ID, client secret, and an error if credentials are not found.
func (controller *OIDCController) getClientCredentials(c *gin.Context) (string, string, error) {
	// Try Basic Auth first (client_secret_basic)
	authHeader := c.GetHeader("Authorization")
	if strings.HasPrefix(authHeader, "Basic ") {
		encoded := strings.TrimPrefix(authHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				return parts[0], parts[1], nil
			}
		}
	}

	// Try POST form parameters (client_secret_post)
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	if clientID != "" && clientSecret != "" {
		return clientID, clientSecret, nil
	}

	// Do not accept credentials via query parameters as they are logged
	// in access logs, browser history, and referrer headers
	return "", "", fmt.Errorf("client credentials not found")
}

// getAccessToken extracts the access token from the request.
// Checks the Authorization header (Bearer token) first, then falls back to
// the access_token query parameter.
// Returns an empty string if no access token is found.
func (controller *OIDCController) getAccessToken(c *gin.Context) string {
	// Try Authorization header
	authHeader := c.GetHeader("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Try query parameter
	return c.Query("access_token")
}

// validateAccessToken validates an access token and extracts user context.
// Verifies the JWT signature using the OIDC service's public key, checks the
// issuer, and validates expiration. Returns the user context if valid, or an
// error if validation fails.
func (controller *OIDCController) validateAccessToken(accessToken string) (*config.UserContext, error) {
	// Validate the JWT token using the OIDC service's public key
	// This properly verifies the signature, issuer, and expiration
	// Note: This method does not validate audience - use ValidateAccessTokenForClient for that
	return controller.oidc.ValidateAccessToken(accessToken)
}
