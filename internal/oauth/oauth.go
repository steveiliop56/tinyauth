package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"golang.org/x/oauth2"
)

func NewOAuth(config oauth2.Config) *OAuth {
	return &OAuth{
		Config: config,
	}
}

type OAuth struct {
	Config   oauth2.Config
	Context  context.Context
	Token    *oauth2.Token
	Verifier string
}

func (oauth *OAuth) Init() {
	// Create a new context and verifier
	oauth.Context = context.Background()
	oauth.Verifier = oauth2.GenerateVerifier()
}

func (oauth *OAuth) GetAuthURL(state string) string {
	// Return the auth url
	return oauth.Config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(oauth.Verifier))
}

func (oauth *OAuth) ExchangeToken(code string) (*oauth2.Token, error) {
	// Exchange the code for a token
	token, err := oauth.Config.Exchange(oauth.Context, code, oauth2.VerifierOption(oauth.Verifier))

	// Check if there was an error
	if err != nil {
		// Return nil token on error
		return nil, err
	}

	// Set the token internally (optional, depending on if you need it stored in the OAuth struct later)
	oauth.Token = token

	// Return the full token object
	return token, nil
}

func (oauth *OAuth) GetClient() *http.Client {
	// Return the http client with the token set
	return oauth.Config.Client(oauth.Context, oauth.Token)
}

func (oauth *OAuth) GenerateState() string {
	// Generate a random state string
	b := make([]byte, 128)

	// Fill the byte slice with random data
	rand.Read(b)

	// Encode the byte slice to a base64 string
	state := base64.URLEncoding.EncodeToString(b)

	return state
}
