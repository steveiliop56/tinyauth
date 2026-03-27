package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/steveiliop56/tinyauth/internal/config"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

var GoogleOAuthScopes = []string{"openid", "email", "profile"}

type GoogleOAuthService struct {
	config   oauth2.Config
	context  context.Context
	token    *oauth2.Token
	verifier string
	name     string
}

func NewGoogleOAuthService(config config.OAuthServiceConfig) *GoogleOAuthService {
	return &GoogleOAuthService{
		config: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Scopes:       GoogleOAuthScopes,
			Endpoint:     endpoints.Google,
		},
		name: config.Name,
	}
}

func (google *GoogleOAuthService) Init() error {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	google.context = ctx
	return nil
}

func (oauth *GoogleOAuthService) GenerateState() string {
	b := make([]byte, 128)
	_, err := rand.Read(b)
	if err != nil {
		return base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, "state-%d", time.Now().UnixNano()))
	}
	state := base64.RawURLEncoding.EncodeToString(b)
	return state
}

func (google *GoogleOAuthService) GenerateVerifier() string {
	verifier := oauth2.GenerateVerifier()
	google.verifier = verifier
	return verifier
}

func (google *GoogleOAuthService) GetAuthURL(state string) string {
	return google.config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(google.verifier))
}

func (google *GoogleOAuthService) VerifyCode(code string) error {
	token, err := google.config.Exchange(google.context, code, oauth2.VerifierOption(google.verifier))

	if err != nil {
		return err
	}

	google.token = token
	return nil
}

func (google *GoogleOAuthService) Userinfo() (config.Claims, error) {
	var user config.Claims

	client := google.config.Client(google.context, google.token)

	res, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")
	if err != nil {
		return config.Claims{}, err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return user, fmt.Errorf("request failed with status: %s", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return config.Claims{}, err
	}

	err = json.Unmarshal(body, &user)
	if err != nil {
		return config.Claims{}, err
	}

	user.PreferredUsername = strings.SplitN(user.Email, "@", 2)[0]

	return user, nil
}

func (google *GoogleOAuthService) GetName() string {
	return google.name
}

// GetToken returns the current OAuth token (after VerifyCode has been called)
func (google *GoogleOAuthService) GetToken() *oauth2.Token {
	return google.token
}

// RefreshToken is not supported for Google OAuth (no group-based ACLs)
func (google *GoogleOAuthService) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("token refresh not supported for Google OAuth")
}
