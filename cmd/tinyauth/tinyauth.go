package main

import (
	"fmt"

	"github.com/steveiliop56/tinyauth/internal/bootstrap"
	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/utils"
	"github.com/steveiliop56/tinyauth/internal/utils/loaders"

	"github.com/rs/zerolog/log"
	"github.com/traefik/paerser/cli"
)

func NewTinyauthCmdConfiguration() *config.Config {
	return &config.Config{
		ResourcesDir: "./resources",
		DatabasePath: "./tinyauth.db",
		Server: config.ServerConfig{
			Port:    3000,
			Address: "0.0.0.0",
		},
		Auth: config.AuthConfig{
			SessionExpiry:      3600,
			SessionMaxLifetime: 0,
			LoginTimeout:       300,
			LoginMaxRetries:    3,
		},
		UI: config.UIConfig{
			Title:                 "Tinyauth",
			ForgotPasswordMessage: "You can change your password by changing the configuration.",
			BackgroundImage:       "/background.jpg",
		},
		Ldap: config.LdapConfig{
			Insecure:     false,
			SearchFilter: "(uid=%s)",
		},
		Log: config.LogConfig{
			Level: "info",
			Json:  false,
		},
		Experimental: config.ExperimentalConfig{
			ConfigFile: "",
		},
	}
}

func main() {
	tConfig := NewTinyauthCmdConfiguration()

	loaders := []cli.ResourceLoader{
		&loaders.FileLoader{},
		&loaders.FlagLoader{},
		&loaders.EnvLoader{},
	}

	cmdTinyauth := &cli.Command{
		Name:          "tinyauth",
		Description:   "The simplest way to protect your apps with a login screen.",
		Configuration: tConfig,
		Resources:     loaders,
		Run: func(_ []string) error {
			return runCmd(*tConfig)
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

func runCmd(cfg config.Config) error {
	outputs := make(map[string]utils.LoggerOutputConfig)
	for name, out := range cfg.Log.Outputs {
		outputs[name] = utils.LoggerOutputConfig{
			Enabled: out.Enabled,
			Level:   out.Level,
		}
	}

	err := utils.InitLogger(&utils.LoggerConfig{
		Level:   cfg.Log.Level,
		Json:    cfg.Log.Json,
		Outputs: outputs,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize logger")
	}

	utils.Log.App.Info().Str("version", config.Version).Msg("Starting tinyauth")

	app := bootstrap.NewBootstrapApp(cfg)

	err = app.Setup()

	if err != nil {
		return fmt.Errorf("failed to bootstrap app: %w", err)
	}

	return nil
}
