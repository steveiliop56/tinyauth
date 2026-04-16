package loaders

import (
	"os"

	"github.com/rs/zerolog/log"
	"github.com/tinyauthapp/paerser/cli"
	"github.com/tinyauthapp/paerser/file"
	"github.com/tinyauthapp/paerser/flag"
)

type FileLoader struct{}

func (f *FileLoader) Load(args []string, cmd *cli.Command) (bool, error) {
	flags, err := flag.Parse(args, cmd.Configuration)

	if err != nil {
		return false, err
	}

	// I guess we are using traefik as the root name (we can't change it)
	configFileFlag := "traefik.experimental.configfile"
	envVar := "TINYAUTH_EXPERIMENTAL_CONFIGFILE"

	if _, ok := flags[configFileFlag]; !ok {
		if value := os.Getenv(envVar); value != "" {
			flags[configFileFlag] = value
		} else {
			return false, nil
		}
	}

	log.Warn().Msg("Using experimental file config loader, this feature is experimental and may change or be removed in future releases")

	err = file.Decode(flags[configFileFlag], cmd.Configuration)

	if err != nil {
		return false, err
	}

	return true, nil
}
