package create

import (
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

var interactive bool
var username string
var password string
var docker bool

var CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a user",
	Long:  `Create a user either interactively or by passing flags.`,
	Run: func(cmd *cobra.Command, args []string) {
		if interactive {
			form := huh.NewForm(
				huh.NewGroup(
					huh.NewInput().Title("Username").Value(&username).Validate((func(s string) error {
						if s == "" {
							return errors.New("username cannot be empty")
						}
						return nil
					})),
					huh.NewInput().Title("Password").Value(&password).Validate((func(s string) error {
						if s == "" {
							return errors.New("password cannot be empty")
						}
						return nil
					})),
					huh.NewSelect[bool]().Title("Format the output for docker?").Options(huh.NewOption("Yes", true), huh.NewOption("No", false)).Value(&docker),
				),
			)

			var baseTheme *huh.Theme = huh.ThemeBase()

			formErr := form.WithTheme(baseTheme).Run()

			if formErr != nil {
				log.Fatal().Err(formErr).Msg("Form failed")
			}
		}

		if username == "" || password == "" {
			log.Error().Msg("Username and password cannot be empty")
		}

		log.Info().Str("username", username).Str("password", password).Bool("docker", docker).Msg("Creating user")

		passwordByte, passwordErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		if passwordErr != nil {
			log.Fatal().Err(passwordErr).Msg("Failed to hash password")
		}

		passwordString := string(passwordByte)

		if docker {
			passwordString = strings.ReplaceAll(passwordString, "$", "$$")
		}

		log.Info().Str("user", fmt.Sprintf("%s:%s", username, passwordString)).Msg("User created")
	},
}

func init() {
	CreateCmd.Flags().BoolVar(&interactive, "interactive", false, "Create a user interactively")
	CreateCmd.Flags().BoolVar(&docker, "docker", false, "Format output for docker")
	CreateCmd.Flags().StringVar(&username, "username", "", "Username")
	CreateCmd.Flags().StringVar(&password, "password", "", "Password")
}
