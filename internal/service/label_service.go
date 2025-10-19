package service

import (
	"os"
	"strings"
	"tinyauth/internal/config"
	"tinyauth/internal/utils/decoders"

	"github.com/rs/zerolog/log"
)

type LabelService struct {
	labelsFoundInEnv bool
	labels           config.Apps
}

func NewLabelService() *LabelService {
	return &LabelService{}
}

func (label *LabelService) Init() error {
	envVars := os.Environ()
	// Check if any TINYAUTH_APPS_ environment variables exist
	var tinyauthAppEnvVars []string
	for _, e := range envVars {
		if strings.HasPrefix(e, "TINYAUTH_APPS_") {
			tinyauthAppEnvVars = append(tinyauthAppEnvVars, e)
		}
	}

	// If found, load labels from environment variables
	if len(tinyauthAppEnvVars) > 0 {
		log.Debug().Msg("TINYAUTH_APPS_ environment variables found, initializing LabelService")
		return label.LoadLabels(tinyauthAppEnvVars)
	}
	log.Debug().Msg("No TINYAUTH_APPS_ environment variables found")
	label.labelsFoundInEnv = false
	return nil
}

func (label *LabelService) LoadLabels(envVars []string) error {
	// Load environment variables and map them to label format
	labelsFromEnv := make(map[string]string)
	for _, e := range envVars {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			key := parts[0]

			// Convert to label format
			// e.g. TINYAUTH_APPS_[APP]_CONFIG_DOMAIN → tinyauth.apps.[app].config.domain
			key = strings.ToLower(key)
			key = strings.ReplaceAll(key, "_", ".")

			value := parts[1]
			labelsFromEnv[key] = value
		}
	}

	// Decode converted labels using some decoder package as Docker labels
	labels, err := decoders.DecodeLabels(labelsFromEnv)
	if err != nil {
		return err
	}

	log.Debug().Msg("Labels loaded from environment variables successfully")
	label.labels = labels
	label.labelsFoundInEnv = true
	return nil
}

func (label *LabelService) GetLabels(appDomain string) (config.App, error) {
	// If no labels found in env, return empty labels
	if !label.labelsFoundInEnv {
		log.Debug().Msg("No labels found in environment, returning empty labels")
		return config.App{}, nil
	}
	// Find matching app by domain or app name
	for appName, appLabels := range label.labels.Apps {
		if appLabels.Config.Domain == appDomain {
			log.Debug().Str("name", appName).Msg("Found matching label by domain")
			return appLabels, nil
		}

		if strings.SplitN(appDomain, ".", 2)[0] == appName {
			log.Debug().Str("name", appName).Msg("Found matching label by app name")
			return appLabels, nil
		}
	}

	log.Debug().Msg("No matching env found, returning empty labels")
	return config.App{}, nil
}
