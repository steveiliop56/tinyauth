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

// Interactive flag
var interactive bool

// Docker flag
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
			err := form.WithTheme(baseTheme).Run()

			if err != nil {
				log.Fatal().Err(err).Msg("Form failed")
			}
		}

		// Parse user
		user, err := utils.ParseUser(iUser)

		if err != nil {
			log.Fatal().Err(err).Msg("Failed to parse user")
		}

		// Compare username
		if user.Username != iUsername {
			log.Fatal().Msg("Username is incorrect")
		}

		// Compare password
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(iPassword))

		if err != nil {
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
		ok := totp.Validate(iTotp, user.TotpSecret)

		if !ok {
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
