package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"tinyauth/internal/config"

	"golang.org/x/oauth2"
)

var GoogleOAuthScopes = []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"}

type GoogleUserInfoResponse struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

type GoogleOAuthService struct {
	Config   oauth2.Config
	Context  context.Context
	Token    *oauth2.Token
	Verifier string
}

func NewGoogleOAuthService(config config.OAuthServiceConfig) *GoogleOAuthService {
	return &GoogleOAuthService{
		Config: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Scopes:       GoogleOAuthScopes,
		},
	}
}

func (google *GoogleOAuthService) Init() error {
	httpClient := &http.Client{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	verifier := oauth2.GenerateVerifier()

	google.Context = ctx
	google.Verifier = verifier
	return nil
}

func (oauth *GoogleOAuthService) GenerateState() string {
	b := make([]byte, 128)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	return state
}

func (google *GoogleOAuthService) GetAuthURL(state string) string {
	return google.Config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(google.Verifier))
}

func (google *GoogleOAuthService) VerifyCode(code string) error {
	token, err := google.Config.Exchange(google.Context, code, oauth2.VerifierOption(google.Verifier))

	if err != nil {
		return nil
	}

	google.Token = token
	return nil
}

func (google *GoogleOAuthService) Userinfo() (config.Claims, error) {
	var user config.Claims

	client := google.Config.Client(google.Context, google.Token)

	res, err := client.Get("https://www.googleapis.com/userinfo/v2/me")
	if err != nil {
		return config.Claims{}, err
	}
	defer res.Body.Close()

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
