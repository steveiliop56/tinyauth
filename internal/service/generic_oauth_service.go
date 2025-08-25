package service

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"tinyauth/internal/config"

	"golang.org/x/oauth2"
)

type GenericOAuthService struct {
	Config             oauth2.Config
	Context            context.Context
	Token              *oauth2.Token
	Verifier           string
	InsecureSkipVerify bool
	UserinfoURL        string
}

func NewGenericOAuthService(config config.OAuthServiceConfig) *GenericOAuthService {
	return &GenericOAuthService{
		Config: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURL,
			Scopes:       config.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.AuthURL,
				TokenURL: config.TokenURL,
			},
		},
		InsecureSkipVerify: config.InsecureSkipVerify,
		UserinfoURL:        config.UserinfoURL,
	}
}

func (generic *GenericOAuthService) Init() error {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: generic.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		},
	}

	httpClient := &http.Client{
		Transport: transport,
	}

	ctx := context.Background()

	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	verifier := oauth2.GenerateVerifier()

	generic.Context = ctx
	generic.Verifier = verifier
	return nil
}

func (generic *GenericOAuthService) GenerateState() string {
	b := make([]byte, 128)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	return state
}

func (generic *GenericOAuthService) GetAuthURL(state string) string {
	return generic.Config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(generic.Verifier))
}

func (generic *GenericOAuthService) VerifyCode(code string) error {
	token, err := generic.Config.Exchange(generic.Context, code, oauth2.VerifierOption(generic.Verifier))

	if err != nil {
		return nil
	}

	generic.Token = token
	return nil
}

func (generic *GenericOAuthService) Userinfo() (config.Claims, error) {
	var user config.Claims

	client := generic.Config.Client(generic.Context, generic.Token)

	res, err := client.Get(generic.UserinfoURL)
	if err != nil {
		return user, err
	}
	defer res.Body.Close()

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
