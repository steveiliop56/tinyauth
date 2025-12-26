package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/steveiliop56/tinyauth/internal/config"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

var GoogleOAuthScopes = []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"}

type GoogleUserInfoResponse struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

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

	res, err := client.Get("https://www.googleapis.com/userinfo/v2/me")
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

	var userInfo GoogleUserInfoResponse

	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return config.Claims{}, err
	}

	user.PreferredUsername = strings.Split(userInfo.Email, "@")[0]
	user.Name = userInfo.Name
	user.Email = userInfo.Email

	return user, nil
}

func (google *GoogleOAuthService) GetName() string {
	return google.name
}
