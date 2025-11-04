package service

import (
	"strings"
	"tinyauth/internal/config"

	"github.com/rs/zerolog/log"
)

type AccessControlsService struct {
	docker    *DockerService
	nonDocker config.Apps
}

func NewAccessControlsService(docker *DockerService, nonDocker config.Apps) *AccessControlsService {
	return &AccessControlsService{
		docker:    docker,
		nonDocker: nonDocker,
	}
}

func (acls *AccessControlsService) Init() error {
	return nil
}

func (acls *AccessControlsService) lookupNonDockerACLs(appDomain string) *config.App {
	if len(acls.nonDocker.Apps) == 0 {
		return nil
	}

	for appName, appACLs := range acls.nonDocker.Apps {
		if appACLs.Config.Domain == appDomain {
			return &appACLs
		}

		if strings.SplitN(appDomain, ".", 2)[0] == appName {
			return &appACLs
		}
	}

	return nil
}

func (acls *AccessControlsService) GetAccessControls(appDomain string) (config.App, error) {
	// First check non-docker apps
	envACLs := acls.lookupNonDockerACLs(appDomain)

	if envACLs != nil {
		log.Debug().Str("domain", appDomain).Msg("Found matching access controls in environment variables or flags")
		return *envACLs, nil
	}

	// Fallback to Docker labels
	return acls.docker.GetLabels(appDomain)
}
