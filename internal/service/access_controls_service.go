package service

import (
	"errors"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/steveiliop56/tinyauth/internal/config"
)

type AccessControlsService struct {
	docker *DockerService
	static map[string]config.App
}

func NewAccessControlsService(docker *DockerService, static map[string]config.App) *AccessControlsService {
	return &AccessControlsService{
		docker: docker,
		static: static,
	}
}

func (acls *AccessControlsService) Init() error {
	return nil // No initialization needed
}

func (acls *AccessControlsService) lookupStaticACLs(domain string) (config.App, error) {
	for app, config := range acls.static {
		if config.Config.Domain == domain {
			log.Debug().Str("name", app).Msg("Found matching container by domain")
			return config, nil
		}

		if strings.SplitN(domain, ".", 2)[0] == app {
			log.Debug().Str("name", app).Msg("Found matching container by app name")
			return config, nil
		}
	}
	return config.App{}, errors.New("no results")
}

func (acls *AccessControlsService) GetAccessControls(domain string) (config.App, error) {
	// First check in the static config
	app, err := acls.lookupStaticACLs(domain)

	if err == nil {
		log.Debug().Msg("Using ACls from static configuration")
		return app, nil
	}

	// Fallback to Docker labels
	log.Debug().Msg("Falling back to Docker labels for ACLs")
	return acls.docker.GetLabels(domain)
}
