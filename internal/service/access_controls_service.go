package service

import (
	"os"
	"strings"
	"tinyauth/internal/config"
	"tinyauth/internal/utils"

	"github.com/rs/zerolog/log"
)

type AccessControlsService struct {
	docker   *DockerService
	envACLs  config.Apps
	aclFlags map[string]string
}

func NewAccessControlsService(docker *DockerService) *AccessControlsService {
	return &AccessControlsService{
		docker:   docker,
		aclFlags: make(map[string]string),
	}
}

func (acls *AccessControlsService) SetACLFlags(flags map[string]string) {
	acls.aclFlags = flags
}

func (acls *AccessControlsService) Init() error {
	env := os.Environ()

	apps, err := utils.GetACLsConfig(env, acls.aclFlags)

	if err != nil {
		return err
	}

	acls.envACLs = apps

	return nil
}

func (acls *AccessControlsService) lookupEnvACLs(appDomain string) *config.App {
	if len(acls.envACLs.Apps) == 0 {
		return nil
	}

	for appName, appACLs := range acls.envACLs.Apps {
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
	// First check environment variables
	envACLs := acls.lookupEnvACLs(appDomain)

	if envACLs != nil {
		log.Debug().Str("domain", appDomain).Msg("Found matching access controls in environment variables")
		return *envACLs, nil
	}

	// Fallback to Docker labels
	return acls.docker.GetLabels(appDomain)
}
