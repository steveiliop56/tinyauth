package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/traefik/paerser/cli"
	"golang.org/x/crypto/bcrypt"
)

type CreateUserConfig struct {
	Interactive bool   `description:"Create a user interactively."`
	Docker      bool   `description:"Format output for docker."`
	Username    string `description:"Username."`
	Password    string `description:"Password."`
}

func NewCreateUserConfig() *CreateUserConfig {
	return &CreateUserConfig{
		Interactive: false,
		Docker:      false,
		Username:    "",
		Password:    "",
	}
}

func createUserCmd() *cli.Command {
	tCfg := NewCreateUserConfig()

	loaders := []cli.ResourceLoader{
		&cli.FlagLoader{},
	}

	return &cli.Command{
		Name:          "create",
		Description:   "Create a user",
		Configuration: tCfg,
		Resources:     loaders,
		Run: func(_ []string) error {
			log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Caller().Logger().Level(zerolog.InfoLevel)

			if tCfg.Interactive {
				form := huh.NewForm(
					huh.NewGroup(
						huh.NewInput().Title("Username").Value(&tCfg.Username).Validate((func(s string) error {
							if s == "" {
								return errors.New("username cannot be empty")
							}
							return nil
						})),
						huh.NewInput().Title("Password").Value(&tCfg.Password).Validate((func(s string) error {
							if s == "" {
								return errors.New("password cannot be empty")
							}
							return nil
						})),
						huh.NewSelect[bool]().Title("Format the output for Docker?").Options(huh.NewOption("Yes", true), huh.NewOption("No", false)).Value(&tCfg.Docker),
					),
				)

				var baseTheme *huh.Theme = huh.ThemeBase()

				err := form.WithTheme(baseTheme).Run()

				if err != nil {
					return fmt.Errorf("failed to run interactive prompt: %w", err)
				}
			}

			if tCfg.Username == "" || tCfg.Password == "" {
				return errors.New("username and password cannot be empty")
			}

			log.Info().Str("username", tCfg.Username).Msg("Creating user")

			passwd, err := bcrypt.GenerateFromPassword([]byte(tCfg.Password), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("failed to hash password: %w", err)
			}

			// If docker format is enabled, escape the dollar sign
			passwdStr := string(passwd)
			if tCfg.Docker {
				passwdStr = strings.ReplaceAll(passwdStr, "$", "$$")
			}

			log.Info().Str("user", fmt.Sprintf("%s:%s", tCfg.Username, passwdStr)).Msg("User created")

			return nil
		},
	}
}
