package service

import (
	"errors"
	"tinyauth/internal/config"

	"github.com/rs/zerolog/log"
)

type OAuthService interface {
	Init() error
	GenerateState() string
	GetAuthURL(state string) string
	VerifyCode(code string) error
	Userinfo() (config.Claims, error)
}

type OAuthBrokerService struct {
	Services map[string]OAuthService
	Configs  map[string]config.OAuthServiceConfig
}

func NewOAuthBrokerService(configs map[string]config.OAuthServiceConfig) *OAuthBrokerService {
	return &OAuthBrokerService{
		Services: make(map[string]OAuthService),
		Configs:  configs,
	}
}

func (broker *OAuthBrokerService) Init() error {
	for name, cfg := range broker.Configs {
		switch name {
		case "github":
			service := NewGithubOAuthService(cfg)
			broker.Services[name] = service
		case "google":
			service := NewGoogleOAuthService(cfg)
			broker.Services[name] = service
		default:
			service := NewGenericOAuthService(cfg)
			broker.Services[name] = service
		}
	}

	for name, service := range broker.Services {
		err := service.Init()
		if err != nil {
			log.Error().Err(err).Msgf("Failed to initialize OAuth service: %s", name)
			return err
		}
		log.Info().Msgf("Initialized OAuth service: %s", name)
	}

	return nil
}

func (broker *OAuthBrokerService) GetConfiguredServices() []string {
	services := make([]string, 0, len(broker.Services))
	for name := range broker.Services {
		services = append(services, name)
	}
	return services
}

func (broker *OAuthBrokerService) GetService(name string) (OAuthService, bool) {
	service, exists := broker.Services[name]
	return service, exists
}

func (broker *OAuthBrokerService) GetUser(service string) (config.Claims, error) {
	oauthService, exists := broker.Services[service]
	if !exists {
		return config.Claims{}, errors.New("oauth service not found")
	}
	return oauthService.Userinfo()
}
