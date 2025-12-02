package service

import (
	"errors"
	"tinyauth/internal/config"

	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
)

type OAuthService interface {
	Init() error
	GenerateState() string
	GenerateVerifier() string
	GetAuthURL(state string) string
	VerifyCode(code string) error
	Userinfo() (config.Claims, error)
	GetName() string
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
			log.Error().Err(err).Msgf("Failed to initialize OAuth service: %T", name)
			return err
		}
		log.Info().Str("service", name).Msg("Initialized OAuth service")
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
