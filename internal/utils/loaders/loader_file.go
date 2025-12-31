package loaders

import (
	"github.com/rs/zerolog/log"
	"github.com/traefik/paerser/cli"
	"github.com/traefik/paerser/file"
	"github.com/traefik/paerser/flag"
)

type FileLoader struct{}

func (f *FileLoader) Load(args []string, cmd *cli.Command) (bool, error) {
	flags, err := flag.Parse(args, cmd.Configuration)

	if err != nil {
		return false, err
	}

	// Check for experimental config file flag (supports both traefik.* and direct format)
	// Note: paerser converts flags to lowercase, so we check lowercase versions
	configFilePath := ""
	if val, ok := flags["traefik.experimental.configfile"]; ok {
		configFilePath = val
	} else if val, ok := flags["experimental.configfile"]; ok {
		configFilePath = val
	}

	if configFilePath == "" {
		return false, nil
	}

	log.Warn().Str("configFile", configFilePath).Msg("Using experimental file config loader, this feature is experimental and may change or be removed in future releases")

	err = file.Decode(configFilePath, cmd.Configuration)

	if err != nil {
		log.Error().Err(err).Str("configFile", configFilePath).Msg("Failed to decode config file")
		return false, err
	}

	return true, nil
}
