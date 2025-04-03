package oauth

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

func NewOAuth(config oauth2.Config) *OAuth {
	return &OAuth{
		Config: config,
	}
}

type OAuth struct {
	Verifier string
	Context  context.Context
	Token    *oauth2.Token
	Config   oauth2.Config
}

func (oauth *OAuth) Init() {
	// Create a new context and verifier
	oauth.Context = context.Background()
	oauth.Verifier = oauth2.GenerateVerifier()
}

func (oauth *OAuth) GetAuthURL() string {
	// Return the auth url
	return oauth.Config.AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(oauth.Verifier))
}

func (oauth *OAuth) ExchangeToken(code string) (string, error) {
	// Exchange the code for a token
	token, err := oauth.Config.Exchange(oauth.Context, code, oauth2.VerifierOption(oauth.Verifier))

	// Check if there was an error
	if err != nil {
		return "", err
	}

	// Set the token
	oauth.Token = token

	// Return the access token
	return oauth.Token.AccessToken, nil
}

func (oauth *OAuth) GetClient() *http.Client {
	// Return the http client with the token set
	return oauth.Config.Client(oauth.Context, oauth.Token)
}
