package oauth

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"net/http"

	"golang.org/x/oauth2"
)

type OAuth struct {
	Config   oauth2.Config
	Context  context.Context
	Token    *oauth2.Token
	Verifier string
}

func NewOAuth(config oauth2.Config, insecureSkipVerify bool) *OAuth {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		},
	}

	httpClient := &http.Client{
		Transport: transport,
	}

	ctx := context.Background()

	// Set the HTTP client in the context
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	verifier := oauth2.GenerateVerifier()

	return &OAuth{
		Config:   config,
		Context:  ctx,
		Verifier: verifier,
	}
}

func (oauth *OAuth) GetAuthURL(state string) string {
	return oauth.Config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(oauth.Verifier))
}

func (oauth *OAuth) ExchangeToken(code string) (string, error) {
	token, err := oauth.Config.Exchange(oauth.Context, code, oauth2.VerifierOption(oauth.Verifier))

	if err != nil {
		return "", err
	}

	// Set and return the token
	oauth.Token = token
	return oauth.Token.AccessToken, nil
}

func (oauth *OAuth) GetClient() *http.Client {
	return oauth.Config.Client(oauth.Context, oauth.Token)
}

func (oauth *OAuth) GenerateState() string {
	b := make([]byte, 128)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	return state
}
