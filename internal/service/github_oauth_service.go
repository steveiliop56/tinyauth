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
	"strconv"
	"time"

	"github.com/steveiliop56/tinyauth/internal/config"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

var GithubOAuthScopes = []string{"user:email", "read:user"}

type GithubEmailResponse []struct {
	Email   string `json:"email"`
	Primary bool   `json:"primary"`
}

type GithubUserInfoResponse struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	ID    int    `json:"id"`
}

type GithubOAuthService struct {
	config   oauth2.Config
	context  context.Context
	token    *oauth2.Token
	verifier string
	name     string
}

func NewGithubOAuthService(config config.OAuthServiceConfig) *GithubOAuthService {
	return &GithubOAuthService{
		config: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Scopes:       GithubOAuthScopes,
			Endpoint:     endpoints.GitHub,
		},
		name: config.Name,
	}
}

func (github *GithubOAuthService) Init() error {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	github.context = ctx
	return nil
}

func (github *GithubOAuthService) GenerateState() string {
	b := make([]byte, 128)
	_, err := rand.Read(b)
	if err != nil {
		return base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, "state-%d", time.Now().UnixNano()))
	}
	state := base64.RawURLEncoding.EncodeToString(b)
	return state
}

func (github *GithubOAuthService) GenerateVerifier() string {
	verifier := oauth2.GenerateVerifier()
	github.verifier = verifier
	return verifier
}

func (github *GithubOAuthService) GetAuthURL(state string) string {
	return github.config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(github.verifier))
}

func (github *GithubOAuthService) VerifyCode(code string) error {
	token, err := github.config.Exchange(github.context, code, oauth2.VerifierOption(github.verifier))

	if err != nil {
		return err
	}

	github.token = token
	return nil
}

func (github *GithubOAuthService) Userinfo() (config.Claims, error) {
	var user config.Claims

	client := github.config.Client(github.context, github.token)

	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return user, err
	}

	req.Header.Set("Accept", "application/vnd.github+json")

	res, err := client.Do(req)
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

	var userInfo GithubUserInfoResponse

	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return user, err
	}

	req, err = http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return user, err
	}

	req.Header.Set("Accept", "application/vnd.github+json")

	res, err = client.Do(req)
	if err != nil {
		return user, err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return user, fmt.Errorf("request failed with status: %s", res.Status)
	}

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
	user.Sub = strconv.Itoa(userInfo.ID)

	return user, nil
}

func (github *GithubOAuthService) GetName() string {
	return github.name
}
