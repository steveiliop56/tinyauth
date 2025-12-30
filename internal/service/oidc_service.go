package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/model"
	"github.com/steveiliop56/tinyauth/internal/utils"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

type OIDCServiceConfig struct {
	AppURL            string
	Issuer            string
	AccessTokenExpiry int
	IDTokenExpiry     int
	Database          *gorm.DB
}

type OIDCService struct {
	config     OIDCServiceConfig
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewOIDCService(config OIDCServiceConfig) *OIDCService {
	return &OIDCService{
		config: config,
	}
}

func (oidc *OIDCService) Init() error {
	// Try to load existing key from database
	var keyRecord model.OIDCKey
	err := oidc.config.Database.First(&keyRecord).Error
	
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("failed to query for existing RSA key: %w", err)
	}

	var privateKey *rsa.PrivateKey

	if err == nil && keyRecord.PrivateKey != "" {
		// Load existing key
		block, _ := pem.Decode([]byte(keyRecord.PrivateKey))
		if block == nil {
			return fmt.Errorf("failed to decode PEM block from stored key")
		}

		parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8 format as fallback
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse stored private key: %w", err)
			}
			var ok bool
			privateKey, ok = key.(*rsa.PrivateKey)
			if !ok {
				return fmt.Errorf("stored key is not an RSA private key")
			}
		} else {
			privateKey = parsedKey
		}

		oidc.privateKey = privateKey
		oidc.publicKey = &privateKey.PublicKey

		log.Info().Msg("OIDC service initialized with existing RSA key pair from database")
		return nil
	}

	// No existing key found, generate new one
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode private key to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Save to database
	now := time.Now().Unix()
	keyRecord = model.OIDCKey{
		PrivateKey: string(privateKeyPEM),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := oidc.config.Database.Create(&keyRecord).Error; err != nil {
		return fmt.Errorf("failed to save RSA key to database: %w", err)
	}

	oidc.privateKey = privateKey
	oidc.publicKey = &privateKey.PublicKey

	log.Info().Msg("OIDC service initialized with new RSA key pair (saved to database)")
	return nil
}

func (oidc *OIDCService) GetClient(clientID string) (*model.OIDCClient, error) {
	var client model.OIDCClient
	err := oidc.config.Database.Where("client_id = ?", clientID).First(&client).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("client not found")
		}
		return nil, err
	}
	return &client, nil
}

func (oidc *OIDCService) VerifyClientSecret(client *model.OIDCClient, secret string) bool {
	return client.ClientSecret == secret
}

func (oidc *OIDCService) ValidateRedirectURI(client *model.OIDCClient, redirectURI string) bool {
	var redirectURIs []string
	if err := json.Unmarshal([]byte(client.RedirectURIs), &redirectURIs); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal redirect URIs")
		return false
	}

	for _, uri := range redirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

func (oidc *OIDCService) ValidateGrantType(client *model.OIDCClient, grantType string) bool {
	var grantTypes []string
	if err := json.Unmarshal([]byte(client.GrantTypes), &grantTypes); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal grant types")
		return false
	}

	for _, gt := range grantTypes {
		if gt == grantType {
			return true
		}
	}
	return false
}

func (oidc *OIDCService) ValidateResponseType(client *model.OIDCClient, responseType string) bool {
	var responseTypes []string
	if err := json.Unmarshal([]byte(client.ResponseTypes), &responseTypes); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal response types")
		return false
	}

	for _, rt := range responseTypes {
		if rt == responseType {
			return true
		}
	}
	return false
}

func (oidc *OIDCService) ValidateScope(client *model.OIDCClient, requestedScopes string) ([]string, error) {
	var allowedScopes []string
	if err := json.Unmarshal([]byte(client.Scopes), &allowedScopes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scopes: %w", err)
	}

	requestedScopesList := []string{}
	if requestedScopes != "" {
		requestedScopesList = splitScopes(requestedScopes)
	}

	validScopes := []string{}
	for _, scope := range requestedScopesList {
		for _, allowed := range allowedScopes {
			if scope == allowed {
				validScopes = append(validScopes, scope)
				break
			}
		}
	}

	// Always include "openid" if it was requested
	hasOpenID := false
	for _, scope := range validScopes {
		if scope == "openid" {
			hasOpenID = true
			break
		}
	}

	if !hasOpenID && contains(requestedScopesList, "openid") {
		validScopes = append(validScopes, "openid")
	}

	return validScopes, nil
}

func (oidc *OIDCService) GenerateAuthorizationCode(userContext *config.UserContext, clientID string, redirectURI string, scopes []string, nonce string, codeChallenge string, codeChallengeMethod string) (string, error) {
	code := uuid.New().String()

	// Store authorization code in a temporary structure
	// In a production system, you'd want to store this in a database with expiry
	authCode := map[string]interface{}{
		"code":        code,
		"userContext": userContext,
		"clientID":    clientID,
		"redirectURI": redirectURI,
		"scopes":      scopes,
		"nonce":       nonce,
		"expiresAt":   time.Now().Add(10 * time.Minute).Unix(),
	}

	// For now, we'll encode it as a JWT for stateless operation
	claims := jwt.MapClaims{
		"code":         code,
		"username":     userContext.Username,
		"email":        userContext.Email,
		"name":         userContext.Name,
		"provider":     userContext.Provider,
		"client_id":    clientID,
		"redirect_uri": redirectURI,
		"scopes":       scopes,
		"exp":          time.Now().Add(10 * time.Minute).Unix(),
		"iat":          time.Now().Unix(),
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	// Store PKCE challenge if provided
	if codeChallenge != "" {
		claims["code_challenge"] = codeChallenge
		if codeChallengeMethod != "" {
			claims["code_challenge_method"] = codeChallengeMethod
		} else {
			// Default to plain if method not specified
			claims["code_challenge_method"] = "plain"
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	codeToken, err := token.SignedString(oidc.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign authorization code: %w", err)
	}

	_ = authCode // Suppress unused variable warning
	return codeToken, nil
}

func (oidc *OIDCService) ValidateAuthorizationCode(codeToken string, clientID string, redirectURI string) (*config.UserContext, []string, string, string, string, error) {
	token, err := jwt.Parse(codeToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return oidc.publicKey, nil
	})

	if err != nil {
		return nil, nil, "", "", "", fmt.Errorf("failed to parse authorization code: %w", err)
	}

	if !token.Valid {
		return nil, nil, "", "", "", errors.New("invalid authorization code")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, "", "", "", errors.New("invalid token claims")
	}

	// Verify client_id and redirect_uri match
	if claims["client_id"] != clientID {
		return nil, nil, "", "", "", errors.New("client_id mismatch")
	}

	if claims["redirect_uri"] != redirectURI {
		return nil, nil, "", "", "", errors.New("redirect_uri mismatch")
	}

	// Check expiration
	exp, ok := claims["exp"].(float64)
	if !ok || time.Now().Unix() > int64(exp) {
		return nil, nil, "", "", "", errors.New("authorization code expired")
	}

	userContext := &config.UserContext{
		Username:   getStringClaim(claims, "username"),
		Email:      getStringClaim(claims, "email"),
		Name:       getStringClaim(claims, "name"),
		Provider:   getStringClaim(claims, "provider"),
		IsLoggedIn: true,
	}

	scopes := []string{}
	if scopesInterface, ok := claims["scopes"].([]interface{}); ok {
		for _, s := range scopesInterface {
			if scope, ok := s.(string); ok {
				scopes = append(scopes, scope)
			}
		}
	}

	nonce := getStringClaim(claims, "nonce")
	codeChallenge := getStringClaim(claims, "code_challenge")
	codeChallengeMethod := getStringClaim(claims, "code_challenge_method")

	return userContext, scopes, nonce, codeChallenge, codeChallengeMethod, nil
}

func (oidc *OIDCService) ValidatePKCE(codeChallenge string, codeChallengeMethod string, codeVerifier string) error {
	if codeChallenge == "" {
		// PKCE not used, validation passes
		return nil
	}

	if codeVerifier == "" {
		return errors.New("code_verifier required when code_challenge is present")
	}

	switch codeChallengeMethod {
	case "S256":
		// Compute SHA256 hash of code_verifier
		hash := sha256.Sum256([]byte(codeVerifier))
		// Base64URL encode (without padding)
		computedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
		if computedChallenge != codeChallenge {
			return errors.New("code_verifier does not match code_challenge")
		}
	case "plain":
		// Direct comparison
		if codeVerifier != codeChallenge {
			return errors.New("code_verifier does not match code_challenge")
		}
	default:
		return fmt.Errorf("unsupported code_challenge_method: %s", codeChallengeMethod)
	}

	return nil
}

func (oidc *OIDCService) GenerateAccessToken(userContext *config.UserContext, clientID string, scopes []string) (string, error) {
	expiry := oidc.config.AccessTokenExpiry
	if expiry <= 0 {
		expiry = 3600 // Default 1 hour
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub":       userContext.Username,
		"iss":       oidc.config.Issuer,
		"aud":       clientID,
		"exp":       now.Add(time.Duration(expiry) * time.Second).Unix(),
		"iat":       now.Unix(),
		"scope":     joinScopes(scopes),
		"client_id": clientID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	accessToken, err := token.SignedString(oidc.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return accessToken, nil
}

func (oidc *OIDCService) ValidateAccessToken(accessToken string) (*config.UserContext, error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return oidc.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse access token: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid access token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Verify issuer
	iss, ok := claims["iss"].(string)
	if !ok || iss != oidc.config.Issuer {
		return nil, errors.New("invalid issuer")
	}

	// Check expiration
	exp, ok := claims["exp"].(float64)
	if !ok || time.Now().Unix() > int64(exp) {
		return nil, errors.New("access token expired")
	}

	// Extract user info from claims
	username, ok := claims["sub"].(string)
	if !ok || username == "" {
		return nil, errors.New("missing sub claim")
	}

	// Extract email and name if available
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)

	// Create user context
	userContext := &config.UserContext{
		Username:   username,
		Email:      email,
		Name:       name,
		IsLoggedIn: true,
	}

	return userContext, nil
}

func (oidc *OIDCService) GenerateIDToken(userContext *config.UserContext, clientID string, nonce string) (string, error) {
	expiry := oidc.config.IDTokenExpiry
	if expiry <= 0 {
		expiry = 3600 // Default 1 hour
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub":                userContext.Username,
		"iss":                oidc.config.Issuer,
		"aud":                clientID,
		"exp":                now.Add(time.Duration(expiry) * time.Second).Unix(),
		"iat":                now.Unix(),
		"auth_time":          now.Unix(),
		"email":              userContext.Email,
		"name":               userContext.Name,
		"preferred_username": userContext.Username,
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	idToken, err := token.SignedString(oidc.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	return idToken, nil
}

func (oidc *OIDCService) GetJWKS() (map[string]interface{}, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(oidc.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Extract modulus and exponent from public key
	n := oidc.publicKey.N
	e := oidc.publicKey.E

	nBytes := n.Bytes()
	eBytes := make([]byte, 4)
	eBytes[0] = byte(e >> 24)
	eBytes[1] = byte(e >> 16)
	eBytes[2] = byte(e >> 8)
	eBytes[3] = byte(e)

	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"kid": "default",
		"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
		"alg": "RS256",
	}

	_ = pubKeyPEM // Suppress unused variable warning

	return map[string]interface{}{
		"keys": []interface{}{jwk},
	}, nil
}

func (oidc *OIDCService) GetIssuer() string {
	return oidc.config.Issuer
}

func (oidc *OIDCService) GetAccessTokenExpiry() int {
	if oidc.config.AccessTokenExpiry <= 0 {
		return 3600 // Default 1 hour
	}
	return oidc.config.AccessTokenExpiry
}

func (oidc *OIDCService) SyncClientsFromConfig(clients map[string]config.OIDCClientConfig) error {
	for clientID, clientConfig := range clients {
		// Get client secret from config or file (similar to OAuth providers)
		clientSecret := utils.GetSecret(clientConfig.ClientSecret, clientConfig.ClientSecretFile)

		if clientSecret == "" {
			log.Warn().Str("client_id", clientID).Msg("Client secret is empty, skipping client")
			continue
		}

		// Set defaults
		clientName := clientConfig.ClientName
		if clientName == "" {
			clientName = clientID
		}

		redirectURIs := clientConfig.RedirectURIs
		if len(redirectURIs) == 0 {
			log.Warn().Str("client_id", clientID).Msg("No redirect URIs configured for client")
			continue
		}

		grantTypes := clientConfig.GrantTypes
		if len(grantTypes) == 0 {
			grantTypes = []string{"authorization_code"}
		}

		responseTypes := clientConfig.ResponseTypes
		if len(responseTypes) == 0 {
			responseTypes = []string{"code"}
		}

		scopes := clientConfig.Scopes
		if len(scopes) == 0 {
			scopes = []string{"openid", "profile", "email"}
		}

		// Serialize arrays to JSON
		redirectURIsJSON, err := json.Marshal(redirectURIs)
		if err != nil {
			log.Error().Err(err).Str("client_id", clientID).Msg("Failed to marshal redirect URIs")
			continue
		}

		grantTypesJSON, err := json.Marshal(grantTypes)
		if err != nil {
			log.Error().Err(err).Str("client_id", clientID).Msg("Failed to marshal grant types")
			continue
		}

		responseTypesJSON, err := json.Marshal(responseTypes)
		if err != nil {
			log.Error().Err(err).Str("client_id", clientID).Msg("Failed to marshal response types")
			continue
		}

		scopesJSON, err := json.Marshal(scopes)
		if err != nil {
			log.Error().Err(err).Str("client_id", clientID).Msg("Failed to marshal scopes")
			continue
		}

		now := time.Now().Unix()

		// Check if client exists
		var existingClient model.OIDCClient
		err = oidc.config.Database.Where("client_id = ?", clientID).First(&existingClient).Error

		client := model.OIDCClient{
			ClientID:      clientID,
			ClientSecret:  clientSecret,
			ClientName:    clientName,
			RedirectURIs:  string(redirectURIsJSON),
			GrantTypes:    string(grantTypesJSON),
			ResponseTypes: string(responseTypesJSON),
			Scopes:        string(scopesJSON),
			UpdatedAt:     now,
		}

		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Create new client
			client.CreatedAt = now
			if err := oidc.config.Database.Create(&client).Error; err != nil {
				log.Error().Err(err).Str("client_id", clientID).Msg("Failed to create OIDC client")
				continue
			}
			log.Info().Str("client_id", clientID).Str("client_name", clientName).Msg("Created OIDC client from config")
		} else if err == nil {
			// Update existing client
			client.CreatedAt = existingClient.CreatedAt // Preserve original creation time
			if err := oidc.config.Database.Where("client_id = ?", clientID).Updates(&client).Error; err != nil {
				log.Error().Err(err).Str("client_id", clientID).Msg("Failed to update OIDC client")
				continue
			}
			log.Info().Str("client_id", clientID).Str("client_name", clientName).Msg("Updated OIDC client from config")
		} else {
			log.Error().Err(err).Str("client_id", clientID).Msg("Failed to check existing OIDC client")
			continue
		}
	}

	return nil
}

// Helper functions

func splitScopes(scopes string) []string {
	if scopes == "" {
		return []string{}
	}
	parts := strings.Split(scopes, " ")
	result := []string{}
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func joinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func getStringClaim(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}
