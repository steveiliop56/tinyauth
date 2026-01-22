package controller

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/repository"
	"github.com/steveiliop56/tinyauth/internal/utils"
	"github.com/steveiliop56/tinyauth/internal/utils/tlog"
)

var (
	SupportedResponseTypes = []string{"code"}
	SupportedScopes        = []string{"openid", "profile", "email", "groups"}
	SupportedGrantTypes    = []string{"authorization_code"}
)

type OIDCControllerConfig struct {
	Clients []config.OIDCClientConfig
	AppURL  string
}

type OIDCController struct {
	config  OIDCControllerConfig
	router  *gin.RouterGroup
	queries *repository.Queries
}

type AuthorizeRequest struct {
	Scope        string `json:"scope" binding:"required"`
	ResponseType string `json:"response_type" binding:"required"`
	ClientID     string `json:"client_id" binding:"required"`
	RedirectURI  string `json:"redirect_uri" binding:"required"`
	State        string `json:"state" binding:"required"`
}

type TokenRequest struct {
	GrantType   string `form:"grant_type" binding:"required"`
	Code        string `form:"code" binding:"required"`
	RedirectURI string `form:"redirect_uri" binding:"required"`
}

type CallbackError struct {
	Error            string `url:"error"`
	ErrorDescription string `url:"error_description"`
	State            string `url:"state"`
}

func NewOIDCController(config OIDCControllerConfig, router *gin.RouterGroup, queries *repository.Queries) *OIDCController {
	return &OIDCController{
		config:  config,
		router:  router,
		queries: queries,
	}
}

func (controller *OIDCController) SetupRoutes() {
	oidcGroup := controller.router.Group("/oidc")
	oidcGroup.GET("/clients/:id", controller.GetClientInfo)
	oidcGroup.POST("/authorize", controller.Authorize)
	oidcGroup.POST("/token", controller.Token)
	oidcGroup.GET("/userinfo", controller.Userinfo)
}

type ClientRequest struct {
	ClientID string `uri:"id" binding:"required"`
}

func (controller *OIDCController) GetClientInfo(c *gin.Context) {
	var req ClientRequest

	err := c.BindUri(&req)
	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	var client *config.OIDCClientConfig

	// Inefficient yeah, but it will be good until we have thousands of clients
	for _, clientCfg := range controller.config.Clients {
		if clientCfg.ClientID == req.ClientID {
			client = &clientCfg
			break
		}
	}

	if client == nil {
		tlog.App.Warn().Str("client_id", req.ClientID).Msg("Client not found")
		c.JSON(404, gin.H{
			"status":  404,
			"message": "Client not found",
		})
		return
	}

	c.JSON(200, gin.H{
		"status": 200,
		"client": &client.ClientID,
		"name":   &client.Name,
	})
}

func (controller *OIDCController) Authorize(c *gin.Context) {
	// Check if we are logged in
	userContext, err := utils.GetContext(c)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to get user context")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	// OIDC stuff
	var req AuthorizeRequest

	err = c.BindJSON(&req)
	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to bind JSON")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	// TODO: All these errors should redirect to the error page with an explanation

	// Validate client ID
	var client *config.OIDCClientConfig

	for _, clientCfg := range controller.config.Clients {
		if clientCfg.ClientID == req.ClientID {
			client = &clientCfg
			break
		}
	}

	if client == nil {
		tlog.App.Warn().Str("client_id", req.ClientID).Msg("Client not found")
		c.JSON(404, gin.H{
			"status":  404,
			"message": "Client not found",
		})
		return
	}

	// Validate redirect URI
	if !slices.Contains(client.TrustedRedirectURLs, req.RedirectURI) {
		tlog.App.Warn().Str("redirect_uri", req.RedirectURI).Msg("Redirect URI not trusted")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	// Validate scopes
	reqScopes := strings.Split(req.Scope, " ")
	keptScopes := make([]string, 0)

	if len(reqScopes) == 0 || strings.TrimSpace(req.Scope) == "" {
		queries, err := query.Values(CallbackError{
			Error:            "invalid_request",
			ErrorDescription: "Missing scope parameter",
			State:            req.State,
		})

		if err != nil {
			tlog.App.Error().Err(err).Msg("Failed to build query")
			c.Redirect(302, fmt.Sprintf("%s/error", controller.config.AppURL))
			return
		}

		c.Redirect(302, fmt.Sprintf("%s/callback?%s", req.RedirectURI, queries.Encode()))
		return
	}

	for _, scope := range reqScopes {
		if slices.Contains(SupportedScopes, scope) {
			keptScopes = append(keptScopes, scope)
			continue
		}
		tlog.App.Warn().Str("scope", scope).Msg("Scope not supported, ignoring")
	}

	// Generate a code and a sub
	code, err := utils.GetRandomString(32)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to generate random string")
		c.Redirect(302, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	sub, err := utils.GetRandomInt(10)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to generate random integer")
		c.Redirect(302, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	expiresAt := time.Now().Add(time.Minute * time.Duration(10)).Unix()

	// Insert the code into the database
	_, err = controller.queries.CreateOidcCode(c, repository.CreateOidcCodeParams{
		Code:        code,
		Sub:         strconv.Itoa(int(sub)),
		Scope:       strings.Join(keptScopes, ","),
		RedirectURI: req.RedirectURI,
		ClientID:    client.ClientID,
		ExpiresAt:   expiresAt,
	})

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to insert code into database")
		c.Redirect(302, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	// We also need a snapshot of the user that authorized this
	userInfoParams := repository.CreateOidcUserInfoParams{
		Sub:               strconv.Itoa(int(sub)),
		Name:              userContext.Name,
		Email:             userContext.Email,
		PreferredUsername: userContext.Username,
		UpdatedAt:         time.Now().Unix(),
	}

	if userContext.Provider == "ldap" {
		userInfoParams.Groups = userContext.LdapGroups
	}

	if userContext.OAuth && len(userContext.OAuthGroups) > 0 {
		userInfoParams.Groups = userContext.OAuthGroups
	}

	_, err = controller.queries.CreateOidcUserInfo(c, userInfoParams)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to insert user info into database")
		c.Redirect(302, fmt.Sprintf("%s/error", controller.config.AppURL))
		return
	}

	// Return code and done
	c.JSON(200, gin.H{
		"status":       200,
		"message":      "Authorized",
		"code":         code,
		"state":        req.State,
		"redirect_uri": req.RedirectURI,
	})
}

func (controller *OIDCController) Token(c *gin.Context) {
	// Get basic auth
	clientId, clientSecret, ok := c.Request.BasicAuth()

	if !ok {
		tlog.App.Error().Msg("Missing token verifier")
		c.JSON(400, gin.H{
			"error": "invalid_request",
		})
		return
	}

	// Ensure client exists
	var client *config.OIDCClientConfig

	for _, clientCfg := range controller.config.Clients {
		if clientCfg.ClientID == clientId {
			client = &clientCfg
			break
		}
	}

	if client == nil {
		tlog.App.Warn().Str("client_id", clientId).Msg("Client not found")
		c.JSON(400, gin.H{
			"error": "invalid_request",
		})
		return
	}

	if client.ClientSecret != clientSecret {
		tlog.App.Warn().Str("client_id", clientId).Msg("Invalid client secret")
		c.JSON(400, gin.H{
			"error": "invalid_client",
		})
		return
	}

	// Get token
	var req TokenRequest

	err := c.Bind(&req)
	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to bind token request")
		c.JSON(400, gin.H{
			"error": "invalid_request",
		})
		return
	}

	// Validate grant type
	if !slices.Contains(SupportedGrantTypes, req.GrantType) {
		tlog.App.Warn().Str("grant_type", req.GrantType).Msg("Unsupported grant type")
		c.JSON(400, gin.H{
			"error": "unsupported_grant_type",
		})
		return
	}

	// Find pending code entry
	entry, err := controller.queries.GetOidcCode(c, req.Code)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to find code in database")
		c.JSON(400, gin.H{
			"error": "invalid_request",
		})
		return
	}

	// Ensure redirect URIs match
	if entry.RedirectURI != req.RedirectURI {
		tlog.App.Warn().Str("redirect_uri", req.RedirectURI).Msg("Redirect URI mismatch")
		c.JSON(400, gin.H{
			"error": "invalid_request",
		})
		return
	}

	// Generate access token
	genToken, err := utils.GetRandomString(29)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to generate access token")
		c.JSON(400, gin.H{
			"error": "invalid_request",
		})
		return
	}

	// Add tinyauth prefix
	token := fmt.Sprintf("ta-%s", genToken)

	// TODO: either add a refresh token or customize token expiry
	expiresAt := time.Now().Add(time.Duration(3600) * time.Second).Unix()

	// Create token entry
	_, err = controller.queries.CreateOidcToken(c, repository.CreateOidcTokenParams{
		Sub:         entry.Sub,
		AccessToken: token,
		Scope:       entry.Scope,
		ClientID:    client.ClientID,
		ExpiresAt:   expiresAt,
	})

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to create token in database")
		c.JSON(400, gin.H{
			"error": "invalid_request",
		})
		return
	}

	// Delete code entry
	err = controller.queries.DeleteOidcCode(c, entry.Code)

	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to delete code in database")
		c.JSON(400, gin.H{
			"error": "invalid_request",
		})
		return
	}

	// Respond with token
	c.JSON(200, gin.H{
		"access_token": token,
		"token_type":   "bearer",
		"expires_in":   3600,
	})
}

func (controller *OIDCController) Userinfo(c *gin.Context) {
	// Get bearer
	authorizationHeader := c.GetHeader("Authorization")

	tokenType, token, ok := strings.Cut(authorizationHeader, " ")

	if !ok {
		tlog.App.Warn().Msg("OIDC userinfo accessed without authorization header")
		c.JSON(401, gin.H{
			"error": "invalid_request",
		})
		return
	}

	if strings.ToLower(tokenType) != "bearer" {
		tlog.App.Warn().Msg("OIDC userinfo accessed with invalid token type")
		c.JSON(401, gin.H{
			"error": "invalid_request",
		})
		return
	}

	// Get token entry
	entry, err := controller.queries.GetOidcToken(c, token)

	if err != nil {
		tlog.App.Err(err).Msg("Failed to get token entry")
		c.JSON(401, gin.H{
			"error": "invalid_request",
		})
		return
	}

	// Get scopes
	scopes := strings.Split(entry.Scope, ",")

	// Check if token is expired
	if time.Now().Unix() > entry.ExpiresAt {
		tlog.App.Warn().Msg("OIDC userinfo accessed with expired token")

		err = controller.queries.DeleteOidcToken(c, entry.AccessToken)
		if err != nil {
			tlog.App.Err(err).Msg("Failed to delete expired token")
		}

		err = controller.queries.DeleteOidcUserInfo(c, entry.Sub)
		if err != nil {
			tlog.App.Err(err).Msg("Failed to delete oidc user info")
		}

		c.JSON(401, gin.H{
			"error": "invalid_request",
		})
		return
	}

	// Get user info
	user, err := controller.queries.GetOidcUserInfo(c, entry.Sub)

	if err != nil {
		tlog.App.Err(err).Msg("Failed to get user entry")
		c.JSON(401, gin.H{
			"error": "invalid_request",
		})
		return
	}

	// If we don't have the openid scope, return an error
	if !slices.Contains(scopes, "openid") {
		tlog.App.Warn().Msg("OIDC userinfo accessed without openid scope")
		c.JSON(401, gin.H{
			"error": "invalid_request",
		})
		return
	}

	// Let's build the response
	res := map[string]any{
		"sub":        user.Sub,
		"updated_at": user.UpdatedAt,
	}

	// If we have the profile scope, add the profile stuff
	if slices.Contains(scopes, "profile") {
		res["name"] = user.Name
		res["preferred_username"] = user.PreferredUsername
	}

	// If we have the email scope, add the email stuff
	if slices.Contains(scopes, "email") {
		res["email"] = user.Email
	}

	// If we have the groups scope, add the groups stuff
	if slices.Contains(scopes, "groups") {
		res["groups"] = user.Groups
	}

	c.JSON(200, res)
}
