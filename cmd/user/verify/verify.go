package verify

import (
	"errors"
	"tinyauth/internal/utils"

	"github.com/charmbracelet/huh"
	"github.com/pquerna/otp/totp"
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
var iTotp string
var iUser string

var VerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a user is set up correctly",
	Long:  `Verify a user is set up correctly meaning that it has a correct username, password and totp code.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Setup logger
		log.Logger = log.Level(zerolog.InfoLevel)

		// Use simple theme
		var baseTheme *huh.Theme = huh.ThemeBase()

		// Check if interactive
		if interactive {
			// Create huh form
			form := huh.NewForm(
				huh.NewGroup(
					huh.NewInput().Title("User (username:hash:totp)").Value(&iUser).Validate((func(s string) error {
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
					huh.NewInput().Title("Totp Code (if setup)").Value(&iTotp),
				),
			)

			// Run form
			formErr := form.WithTheme(baseTheme).Run()

			if formErr != nil {
				log.Fatal().Err(formErr).Msg("Form failed")
			}
		}

		// Parse user
		user, userErr := utils.ParseUser(iUser)

		if userErr != nil {
			log.Fatal().Err(userErr).Msg("Failed to parse user")
		}

		// Compare username
		if user.Username != iUsername {
			log.Fatal().Msg("Username is incorrect")
		}

		// Compare password
		verifyErr := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(iPassword))

		if verifyErr != nil {
			log.Fatal().Msg("Ppassword is incorrect")
		}

		// Check if user has 2fa code
		if user.TotpSecret == "" {
			if iTotp != "" {
				log.Warn().Msg("User does not have 2fa secret")
			}
			log.Info().Msg("User verified")
			return
		}

		// Check totp code
		totpOk := totp.Validate(iTotp, user.TotpSecret)

		if !totpOk {
			log.Fatal().Msg("Totp code incorrect")

		}

		// Done
		log.Info().Msg("User verified")
	},
}

func init() {
	// Flags
	VerifyCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Create a user interactively")
	VerifyCmd.Flags().BoolVar(&docker, "docker", false, "Is the user formatted for docker?")
	VerifyCmd.Flags().StringVar(&iUsername, "username", "", "Username")
	VerifyCmd.Flags().StringVar(&iPassword, "password", "", "Password")
	VerifyCmd.Flags().StringVar(&iTotp, "totp", "", "Totp code")
	VerifyCmd.Flags().StringVar(&iUser, "user", "", "Hash (username:hash:totp combination)")
}
