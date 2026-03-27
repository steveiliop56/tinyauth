package service

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/utils/tlog"

	"golang.org/x/oauth2"
)

type GenericOAuthService struct {
	config             oauth2.Config
	context            context.Context
	token              *oauth2.Token
	verifier           string
	insecureSkipVerify bool
	userinfoUrl        string
	name               string
}

func NewGenericOAuthService(config config.OAuthServiceConfig) *GenericOAuthService {
	return &GenericOAuthService{
		config: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Scopes:       config.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.AuthURL,
				TokenURL: config.TokenURL,
			},
		},
		insecureSkipVerify: config.Insecure,
		userinfoUrl:        config.UserinfoURL,
		name:               config.Name,
	}
}

func (generic *GenericOAuthService) Init() error {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: generic.insecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		},
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	ctx := context.Background()

	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	generic.context = ctx
	return nil
}

func (generic *GenericOAuthService) GenerateState() string {
	b := make([]byte, 128)
	_, err := rand.Read(b)
	if err != nil {
		return base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, "state-%d", time.Now().UnixNano()))
	}
	state := base64.RawURLEncoding.EncodeToString(b)
	return state
}

func (generic *GenericOAuthService) GenerateVerifier() string {
	verifier := oauth2.GenerateVerifier()
	generic.verifier = verifier
	return verifier
}

func (generic *GenericOAuthService) GetAuthURL(state string) string {
	return generic.config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(generic.verifier))
}

func (generic *GenericOAuthService) VerifyCode(code string) error {
	token, err := generic.config.Exchange(generic.context, code, oauth2.VerifierOption(generic.verifier))

	if err != nil {
		return err
	}

	generic.token = token
	return nil
}

func (generic *GenericOAuthService) Userinfo() (config.Claims, error) {
	var user config.Claims

	client := generic.config.Client(generic.context, generic.token)

	res, err := client.Get(generic.userinfoUrl)
	if err != nil {
		return user, err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return user, fmt.Errorf("request failed with status: %s", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return user, err
	}

	tlog.App.Trace().Str("body", string(body)).Msg("Userinfo response body")

	err = json.Unmarshal(body, &user)
	if err != nil {
		return user, err
	}

	// If the userinfo endpoint did not return groups (e.g. Microsoft Entra ID),
	// try to extract them from the ID token which may contain a "groups" claim.
	if user.Groups == nil {
		if idTokenStr, ok := generic.token.Extra("id_token").(string); ok && idTokenStr != "" {
			if groups, err := parseIDTokenGroups(idTokenStr); err == nil {
				tlog.App.Debug().Msg("Extracted groups from ID token (userinfo had none)")
				user.Groups = groups
			} else {
				tlog.App.Debug().Err(err).Msg("Could not extract groups from ID token")
			}
		}
	}

	return user, nil
}

// parseIDTokenGroups decodes the payload of a JWT ID token and extracts the
// "groups" claim. The token signature is not verified here because the token
// was received directly from the token endpoint over TLS in the same request.
func parseIDTokenGroups(idToken string) (any, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims struct {
		Groups any `json:"groups"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT payload: %w", err)
	}

	if claims.Groups == nil {
		return nil, fmt.Errorf("no groups claim in ID token")
	}

	return claims.Groups, nil
}

func (generic *GenericOAuthService) GetName() string {
	return generic.name
}

// GetToken returns the current OAuth token (after VerifyCode has been called)
func (generic *GenericOAuthService) GetToken() *oauth2.Token {
	return generic.token
}

// RefreshToken uses a refresh token to get a new access/ID token.
// Returns a new token containing potentially updated id_token with fresh groups.
func (generic *GenericOAuthService) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("no refresh token provided")
	}

	// Create a token source using the refresh token
	oldToken := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	tokenSource := generic.config.TokenSource(generic.context, oldToken)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	tlog.App.Debug().Msg("Successfully refreshed OAuth token")
	return newToken, nil
}

// ExtractGroupsFromToken extracts groups from an OAuth token's id_token
func ExtractGroupsFromToken(token *oauth2.Token) (any, error) {
	idTokenStr, ok := token.Extra("id_token").(string)
	if !ok || idTokenStr == "" {
		return nil, fmt.Errorf("no id_token in token response")
	}
	return parseIDTokenGroups(idTokenStr)
}
