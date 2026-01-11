package service

import (
	"errors"
	"strings"

	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/utils"
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
			utils.Log.App.Debug().Str("name", app).Msg("Found matching container by domain")
			return config, nil
		}

		if strings.SplitN(domain, ".", 2)[0] == app {
			utils.Log.App.Debug().Str("name", app).Msg("Found matching container by app name")
			return config, nil
		}
	}
	return config.App{}, errors.New("no results")
}

func (acls *AccessControlsService) GetAccessControls(domain string) (config.App, error) {
	// First check in the static config
	app, err := acls.lookupStaticACLs(domain)

	if err == nil {
		utils.Log.App.Debug().Msg("Using ACls from static configuration")
		return app, nil
	}

	// Fallback to Docker labels
	utils.Log.App.Debug().Msg("Falling back to Docker labels for ACLs")
	return acls.docker.GetLabels(domain)
}
