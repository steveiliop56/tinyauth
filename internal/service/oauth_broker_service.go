package service

import (
	"errors"

	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/utils/tlog"

	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"
)

type OAuthService interface {
	Init() error
	GenerateState() string
	GenerateVerifier() string
	GetAuthURL(state string) string
	VerifyCode(code string) error
	Userinfo() (config.Claims, error)
	GetName() string
	// GetToken returns the current OAuth token (after VerifyCode has been called)
	GetToken() *oauth2.Token
	// RefreshToken uses a refresh token to get a new access/ID token
	RefreshToken(refreshToken string) (*oauth2.Token, error)
}

type OAuthBrokerService struct {
	services map[string]OAuthService
	configs  map[string]config.OAuthServiceConfig
}

func NewOAuthBrokerService(configs map[string]config.OAuthServiceConfig) *OAuthBrokerService {
	return &OAuthBrokerService{
		services: make(map[string]OAuthService),
		configs:  configs,
	}
}

func (broker *OAuthBrokerService) Init() error {
	for name, cfg := range broker.configs {
		switch name {
		case "github":
			service := NewGithubOAuthService(cfg)
			broker.services[name] = service
		case "google":
			service := NewGoogleOAuthService(cfg)
			broker.services[name] = service
		default:
			service := NewGenericOAuthService(cfg)
			broker.services[name] = service
		}
	}

	for name, service := range broker.services {
		err := service.Init()
		if err != nil {
			tlog.App.Error().Err(err).Msgf("Failed to initialize OAuth service: %s", name)
			return err
		}
		tlog.App.Info().Str("service", name).Msg("Initialized OAuth service")
	}

	return nil
}

func (broker *OAuthBrokerService) GetConfiguredServices() []string {
	services := make([]string, 0, len(broker.services))
	for name := range broker.services {
		services = append(services, name)
	}
	slices.Sort(services)
	return services
}

func (broker *OAuthBrokerService) GetService(name string) (OAuthService, bool) {
	service, exists := broker.services[name]
	return service, exists
}

func (broker *OAuthBrokerService) GetUser(service string) (config.Claims, error) {
	oauthService, exists := broker.services[service]
	if !exists {
		return config.Claims{}, errors.New("oauth service not found")
	}
	return oauthService.Userinfo()
}

func (broker *OAuthBrokerService) GetServiceConfig(name string) (config.OAuthServiceConfig, bool) {
	cfg, exists := broker.configs[name]
	return cfg, exists
}
