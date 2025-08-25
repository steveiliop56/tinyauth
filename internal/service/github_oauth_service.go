package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"tinyauth/internal/config"

	"golang.org/x/oauth2"
)

var GithubOAuthScopes = []string{"user:email", "read:user"}

type GithubEmailResponse []struct {
	Email   string `json:"email"`
	Primary bool   `json:"primary"`
}

type GithubUserInfoResponse struct {
	Login string `json:"login"`
	Name  string `json:"name"`
}

type GithubOAuthService struct {
	Config   oauth2.Config
	Context  context.Context
	Token    *oauth2.Token
	Verifier string
}

func NewGithubOAuthService(config config.OAuthServiceConfig) *GithubOAuthService {
	return &GithubOAuthService{
		Config: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Scopes:       GithubOAuthScopes,
		},
	}
}

func (github *GithubOAuthService) Init() error {
	httpClient := &http.Client{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	verifier := oauth2.GenerateVerifier()

	github.Context = ctx
	github.Verifier = verifier
	return nil
}

func (github *GithubOAuthService) GenerateState() string {
	b := make([]byte, 128)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	return state
}

func (github *GithubOAuthService) GetAuthURL(state string) string {
	return github.Config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(github.Verifier))
}

func (github *GithubOAuthService) VerifyCode(code string) error {
	token, err := github.Config.Exchange(github.Context, code, oauth2.VerifierOption(github.Verifier))

	if err != nil {
		return nil
	}

	github.Token = token
	return nil
}

func (github *GithubOAuthService) Userinfo() (config.Claims, error) {
	var user config.Claims

	client := github.Config.Client(github.Context, github.Token)

	res, err := client.Get("https://api.github.com/user")
	if err != nil {
		return user, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return user, err
	}

	var userInfo GithubUserInfoResponse

	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return user, err
	}

	res, err = client.Get("https://api.github.com/user/emails")
	if err != nil {
		return user, err
	}
	defer res.Body.Close()

	body, err = io.ReadAll(res.Body)
	if err != nil {
		return user, err
	}

	var emails GithubEmailResponse

	err = json.Unmarshal(body, &emails)
	if err != nil {
		return user, err
	}

	for _, email := range emails {
		if email.Primary {
			user.Email = email.Email
			break
		}
	}

	if len(emails) == 0 {
		return user, errors.New("no emails found")
	}

	// Use first available email if no primary email was found
	if user.Email == "" {
		user.Email = emails[0].Email
	}

	user.PreferredUsername = userInfo.Login
	user.Name = userInfo.Name

	return user, nil
}
