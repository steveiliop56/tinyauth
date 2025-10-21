package service

import (
	"os"
	"strings"
	"tinyauth/internal/config"
	"tinyauth/internal/utils/decoders"

	"github.com/rs/zerolog/log"
)

type AccessControlsService struct {
	docker  *DockerService
	envACLs config.Apps
}

func NewAccessControlsService(docker *DockerService) *AccessControlsService {
	return &AccessControlsService{
		docker: docker,
	}
}

func (acls *AccessControlsService) Init() error {
	acls.envACLs = config.Apps{}
	env := os.Environ()
	appEnvVars := []string{}

	for _, e := range env {
		if strings.HasPrefix(e, "TINYAUTH_APPS_") {
			appEnvVars = append(appEnvVars, e)
		}
	}

	err := acls.loadEnvACLs(appEnvVars)

	if err != nil {
		return err
	}

	return nil
}

func (acls *AccessControlsService) loadEnvACLs(appEnvVars []string) error {
	if len(appEnvVars) == 0 {
		return nil
	}

	envAcls := map[string]string{}

	for _, e := range appEnvVars {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}

		// Normalize key, this should use the same normalization logic as in utils/decoders/decoders.go
		key := parts[0]
		key = strings.ToLower(key)
		key = strings.ReplaceAll(key, "_", ".")
		value := parts[1]
		envAcls[key] = value
	}

	apps, err := decoders.DecodeLabels(envAcls)

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
