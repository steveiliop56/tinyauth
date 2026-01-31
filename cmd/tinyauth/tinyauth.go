package main

import (
	"fmt"

	"github.com/steveiliop56/tinyauth/internal/bootstrap"
	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/utils/loaders"
	"github.com/steveiliop56/tinyauth/internal/utils/tlog"

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
			SessionExpiry:      86400, // 1 day
			SessionMaxLifetime: 0,     // disabled
			LoginTimeout:       300,   // 5 minutes
			LoginMaxRetries:    3,
		},
		UI: config.UIConfig{
			Title:                 "Tinyauth",
			ForgotPasswordMessage: "You can change your password by changing the configuration.",
			BackgroundImage:       "/background.jpg",
		},
		Ldap: config.LdapConfig{
			Insecure:      false,
			SearchFilter:  "(uid=%s)",
			GroupCacheTTL: 900, // 15 minutes
		},
		Log: config.LogConfig{
			Level: "info",
			Json:  false,
			Streams: config.LogStreams{
				HTTP: config.LogStreamConfig{
					Enabled: true,
					Level:   "",
				},
				App: config.LogStreamConfig{
					Enabled: true,
					Level:   "",
				},
				Audit: config.LogStreamConfig{
					Enabled: false,
					Level:   "",
				},
			},
		},
		OIDC: config.OIDCConfig{
			PrivateKeyPath: "./tinyauth_oidc_key",
			PublicKeyPath:  "./tinyauth_oidc_key.pub",
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

	cmdUser := &cli.Command{
		Name:        "user",
		Description: "Utilities for creating and verifying Tinyauth users.",
	}

	cmdTotp := &cli.Command{
		Name:        "totp",
		Description: "Utilities for creating Tinyauth TOTP users.",
	}

	err := cmdTinyauth.AddCommand(versionCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add version command")
	}

	err = cmdUser.AddCommand(verifyUserCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add verify command")
	}

	err = cmdTinyauth.AddCommand(healthcheckCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add healthcheck command")
	}

	err = cmdTotp.AddCommand(generateTotpCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add generate command")
	}

	err = cmdUser.AddCommand(createUserCmd())

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add create command")
	}

	err = cmdTinyauth.AddCommand(cmdUser)

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add user command")
	}

	err = cmdTinyauth.AddCommand(cmdTotp)

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add totp command")
	}

	err = cli.Execute(cmdTinyauth)

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to execute command")
	}
}

func runCmd(cfg config.Config) error {
	logger := tlog.NewLogger(cfg.Log)
	logger.Init()

	tlog.App.Info().Str("version", config.Version).Msg("Starting tinyauth")

	app := bootstrap.NewBootstrapApp(cfg)

	err := app.Setup()

	if err != nil {
		return fmt.Errorf("failed to bootstrap app: %w", err)
	}

	return nil
}
