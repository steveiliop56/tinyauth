package main

import (
	"os"
	"strings"
	"time"
	"tinyauth/internal/config"
	"tinyauth/internal/utils/loaders"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/traefik/paerser/cli"
)

type TinyauthCmdConfiguration struct {
	config.Config
	ConfigFile string `description:"Path to config file."`
}

func NewTinyauthCmdConfiguration() *TinyauthCmdConfiguration {
	return &TinyauthCmdConfiguration{
		Config: config.Config{
			LogLevel: "info",
		},
		ConfigFile: "",
	}
}

func main() {
	tConfig := NewTinyauthCmdConfiguration()

	loaders := []cli.ResourceLoader{
		&loaders.EnvLoader{},
		&loaders.FlagLoader{},
	}

	cmdTinyauth := &cli.Command{
		Name:          "tinyauth",
		Description:   "The simplest way to protect your apps with a login screen.",
		Configuration: tConfig,
		Resources:     loaders,
		Run: func(_ []string) error {
			return runCmd(&tConfig.Config)
		},
	}

	err := cmdTinyauth.AddCommand(versionCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add version command")
	}

	err = cmdTinyauth.AddCommand(verifyUserCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add verify command")
	}

	err = cmdTinyauth.AddCommand(healthcheckCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add healthcheck command")
	}

	err = cmdTinyauth.AddCommand(generateTotpCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add generate command")
	}

	err = cmdTinyauth.AddCommand(createUserCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add create command")
	}

	err = cli.Execute(cmdTinyauth)

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to execute command")
	}
}

func runCmd(cfg *config.Config) error {
	logLevel, err := zerolog.ParseLevel(strings.ToLower(cfg.LogLevel))

	if err != nil {
		log.Error().Err(err).Msg("Invalid or missing log level, defaulting to info")
	} else {
		zerolog.SetGlobalLevel(logLevel)
	}

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Caller().Logger()

	log.Info().Str("version", config.Version).Msg("Starting tinyauth")

	return nil
}
