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

	// I guess we are using traefik as the root name
	configFileFlag := "traefik.experimental.configFile"

	if _, ok := flags[configFileFlag]; !ok {
		return false, nil
	}

	log.Warn().Msg("Using experimental file config loader, this feature is experimental and may change or be removed in future releases")

	err = file.Decode(flags[configFileFlag], cmd.Configuration)

	if err != nil {
		return false, err
	}

	return true, nil
}
