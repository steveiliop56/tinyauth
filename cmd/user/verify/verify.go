package verify

import (
	"errors"
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
var user string

var VerifyCmd = &cobra.Command{
	Use: "verify",
	Short: "Verify a user is set up correctly",
	Long: `Verify a user is set up correctly meaning that it has a correct password.`,
	Run: func(cmd *cobra.Command, args []string) {
		if interactive {
			form := huh.NewForm(
				huh.NewGroup(
					huh.NewInput().Title("User (user:hash)").Value(&user).Validate((func(s string) error {
						if s == "" {
							return errors.New("user cannot be empty")
						}
						return nil
					})),
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
					huh.NewSelect[bool]().Title("Is the user formatted for docker?").Options(huh.NewOption("Yes", true), huh.NewOption("No", false)).Value(&docker),
				),
			)

			var baseTheme *huh.Theme = huh.ThemeBase()

			formErr := form.WithTheme(baseTheme).Run()

			if formErr != nil {
				log.Fatal().Err(formErr).Msg("Form failed")
				os.Exit(1)
			}
		}

		if username == "" || password == "" || user == "" { 
			log.Error().Msg("Username, password and user cannot be empty")
			os.Exit(1)
		}


		log.Info().Str("user", user).Str("username", username).Str("password", password).Bool("docker", docker).Msg("Verifying user")

		userSplit := strings.Split(user, ":")

		if userSplit[1] == "" {
			log.Error().Msg("User is not formatted correctly")
			os.Exit(1)
		}

		if docker {
			userSplit[1] = strings.ReplaceAll(password, "$$", "$")
		}

		verifyErr := bcrypt.CompareHashAndPassword([]byte(userSplit[1]), []byte(password))

		if verifyErr != nil || username != userSplit[0] {
			log.Error().Msg("Username or password incorrect")
			os.Exit(1)
		} else {
			log.Info().Msg("Verification successful")
		}
	},
}

func init() {
	VerifyCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Create a user interactively")
	VerifyCmd.Flags().BoolVar(&docker, "docker", false, "Is the user formatted for docker?")
	VerifyCmd.Flags().StringVar(&username, "username", "", "Username")
	VerifyCmd.Flags().StringVar(&password, "password", "", "Password")
	VerifyCmd.Flags().StringVar(&user, "user", "", "Hash (user:hash combination)")
}