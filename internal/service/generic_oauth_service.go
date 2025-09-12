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
	"time"
	"tinyauth/internal/config"

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
		insecureSkipVerify: config.InsecureSkipVerify,
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
	}

	ctx := context.Background()

	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	verifier := oauth2.GenerateVerifier()

	generic.context = ctx
	generic.verifier = verifier
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

	err = json.Unmarshal(body, &user)
	if err != nil {
		return user, err
	}

	return user, nil
}

func (generic *GenericOAuthService) GetName() string {
	return generic.name
}
