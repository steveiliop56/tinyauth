package verify

import (
	"errors"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

var interactive bool
var docker bool

// i stands for input
var iUsername string
var iPassword string
var iUser string

var VerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a user is set up correctly",
	Long:  `Verify a user is set up correctly meaning that it has a correct username and password.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Setup logger
		log.Logger = log.Level(zerolog.InfoLevel)

		// Check if interactive
		if interactive {
			// Create huh form
			form := huh.NewForm(
				huh.NewGroup(
					huh.NewInput().Title("User (username:hash)").Value(&iUser).Validate((func(s string) error {
						if s == "" {
							return errors.New("user cannot be empty")
						}
						return nil
					})),
					huh.NewInput().Title("Username").Value(&iUsername).Validate((func(s string) error {
						if s == "" {
							return errors.New("username cannot be empty")
						}
						return nil
					})),
					huh.NewInput().Title("Password").Value(&iPassword).Validate((func(s string) error {
						if s == "" {
							return errors.New("password cannot be empty")
						}
						return nil
					})),
					huh.NewSelect[bool]().Title("Is the user formatted for docker?").Options(huh.NewOption("Yes", true), huh.NewOption("No", false)).Value(&docker),
				),
			)

			// Use simple theme
			var baseTheme *huh.Theme = huh.ThemeBase()

			formErr := form.WithTheme(baseTheme).Run()

			if formErr != nil {
				log.Fatal().Err(formErr).Msg("Form failed")
			}
		}

		// Do we have username, password and user?
		if iUsername == "" || iPassword == "" || iUser == "" {
			log.Fatal().Msg("Username, password and user cannot be empty")
		}

		log.Info().Str("user", iUser).Str("username", iUsername).Str("password", iPassword).Bool("docker", docker).Msg("Verifying user")

		// Split username and password hash
		username, hash, ok := strings.Cut(iUser, ":")

		if !ok {
			log.Fatal().Msg("User is not formatted correctly")
		}

		// Replace $$ with $ if formatted for docker
		if docker {
			hash = strings.ReplaceAll(hash, "$$", "$")
		}

		// Compare username and password
		verifyErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(iPassword))

		if verifyErr != nil || username != iUsername {
			log.Fatal().Msg("Username or password incorrect")
		} else {
			log.Info().Msg("Verification successful")
		}
	},
}

func init() {
	// Flags
	VerifyCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Create a user interactively")
	VerifyCmd.Flags().BoolVar(&docker, "docker", false, "Is the user formatted for docker?")
	VerifyCmd.Flags().StringVar(&iUsername, "username", "", "Username")
	VerifyCmd.Flags().StringVar(&iPassword, "password", "", "Password")
	VerifyCmd.Flags().StringVar(&iUser, "user", "", "Hash (username:hash combination)")
}
