package service

import (
	"tinyauth/internal/config"
)

/*
Environment variable/flag based ACLs are disabled until v5 due to a technical challenge
with the current parsing logic.

The current parser works for simple OAuth provider configs like:
- PROVIDERS_MY_AMAZING_PROVIDER_CLIENT_ID

However, it breaks down when handling nested structs required for ACLs. The custom parsing
solution that worked for v4 OAuth providers is incompatible with the ACL parsing logic,
making the codebase unmaintainable and fragile.

A solution is being considered for v5 that would standardize the format to something like:
- TINYAUTH_PROVIDERS_GOOGLE_CLIENTSECRET
- TINYAUTH_APPS_MYAPP_CONFIG_DOMAIN

This would allow the Traefik parser to handle everything consistently, but requires a
config migration. Until this is resolved, environment-based ACLs are disabled and only
Docker label-based ACLs are supported.

See: https://discord.com/channels/1337450123600465984/1337459086270271538/1434986689935179838 for more information
*/

type AccessControlsService struct {
	docker *DockerService
	// envACLs config.Apps
}

func NewAccessControlsService(docker *DockerService) *AccessControlsService {
	return &AccessControlsService{
		docker: docker,
	}
}

func (acls *AccessControlsService) Init() error {
	// acls.envACLs = config.Apps{}
	// env := os.Environ()
	// appEnvVars := []string{}

	// for _, e := range env {
	// 	if strings.HasPrefix(e, "TINYAUTH_APPS_") {
	// 		appEnvVars = append(appEnvVars, e)
	// 	}
	// }

	// err := acls.loadEnvACLs(appEnvVars)

	// if err != nil {
	// 	return err
	// }

	// return nil

	return nil

}

// func (acls *AccessControlsService) loadEnvACLs(appEnvVars []string) error {
// 	if len(appEnvVars) == 0 {
// 		return nil
// 	}

// 	envAcls := map[string]string{}

// 	for _, e := range appEnvVars {
// 		parts := strings.SplitN(e, "=", 2)
// 		if len(parts) != 2 {
// 			continue
// 		}

// 		key := parts[0]
// 		key = strings.ToLower(key)
// 		key = strings.ReplaceAll(key, "_", ".")
// 		value := parts[1]
// 		envAcls[key] = value
// 	}

// 	apps, err := decoders.DecodeLabels(envAcls)

// 	if err != nil {
// 		return err
// 	}

// 	acls.envACLs = apps
// 	return nil
// }

// func (acls *AccessControlsService) lookupEnvACLs(appDomain string) *config.App {
// 	if len(acls.envACLs.Apps) == 0 {
// 		return nil
// 	}

// 	for appName, appACLs := range acls.envACLs.Apps {
// 		if appACLs.Config.Domain == appDomain {
// 			return &appACLs
// 		}

// 		if strings.SplitN(appDomain, ".", 2)[0] == appName {
// 			return &appACLs
// 		}
// 	}

// 	return nil
// }

func (acls *AccessControlsService) GetAccessControls(appDomain string) (config.App, error) {
	// First check environment variables
	// envACLs := acls.lookupEnvACLs(appDomain)

	// if envACLs != nil {
	// 	log.Debug().Str("domain", appDomain).Msg("Found matching access controls in environment variables")
	// 	return *envACLs, nil
	// }

	// Fallback to Docker labels
	return acls.docker.GetLabels(appDomain)
}
