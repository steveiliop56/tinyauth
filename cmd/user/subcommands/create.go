package subcommands

import (
	"errors"
	"fmt"
	"os"
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
	Use:  "create",
	Short: "Create a user",
	Long: `Create a user either interactively or by passing flags.`,
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
					huh.NewConfirm().Title("Format the output for docker?").Value(&docker).Affirmative("Yes").Negative("No"),
				),
			)

			var baseTheme *huh.Theme = huh.ThemeBase()

			formErr := form.WithTheme(baseTheme).Run()

			if formErr != nil {
				log.Fatal().Err(formErr).Msg("Form failed")
				os.Exit(1)
			}
		}

		if username == "" || password == "" {
			log.Error().Msg("Username and password cannot be empty")
			os.Exit(1)
		}

		passwordByte, passwordErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		if passwordErr != nil {
			log.Fatal().Err(passwordErr).Msg("Failed to hash password")
			os.Exit(1)
		}

		passwordString := string(passwordByte)

		if docker {
			passwordString = strings.ReplaceAll(passwordString, "$", "$$")
		}

		log.Info().Str("user", fmt.Sprintf("%s:%s", username, passwordString)).Msg("User created")
	},
}

func init() {
	CreateCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Create a user interactively")
	CreateCmd.Flags().BoolVarP(&docker, "docker", "d", false, "Format output for docker")
	CreateCmd.Flags().StringVarP(&username, "username", "u", "", "Username")
	CreateCmd.Flags().StringVarP(&password, "password", "p", "", "Password")
}