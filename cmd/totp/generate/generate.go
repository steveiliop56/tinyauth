package generate

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"tinyauth/internal/utils"

	"github.com/charmbracelet/huh"
	"github.com/mdp/qrterminal/v3"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// Interactive flag
var interactive bool

// i stands for input
var iUser string

var GenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a totp secret",
	Run: func(cmd *cobra.Command, args []string) {
		// Setup logger
		log.Logger = log.Level(zerolog.InfoLevel)

		// Use simple theme
		var baseTheme *huh.Theme = huh.ThemeBase()

		// Interactive
		if interactive {
			// Create huh form
			form := huh.NewForm(
				huh.NewGroup(
					huh.NewInput().Title("Current username:hash").Value(&iUser).Validate((func(s string) error {
						if s == "" {
							return errors.New("user cannot be empty")
						}
						return nil
					})),
				),
			)

			// Run form
			formErr := form.WithTheme(baseTheme).Run()

			if formErr != nil {
				log.Fatal().Err(formErr).Msg("Form failed")
			}
		}

		// Parse user
		user, parseErr := utils.ParseUser(iUser)

		if parseErr != nil {
			log.Fatal().Err(parseErr).Msg("Failed to parse user")
		}

		// Check if user was using docker escape
		dockerEscape := false

		if strings.Contains(iUser, "$$") {
			dockerEscape = true
		}

		// Check it has totp
		if user.TotpSecret != "" {
			log.Fatal().Msg("User already has a totp secret")
		}

		// Generate totp secret
		key, keyErr := totp.Generate(totp.GenerateOpts{
			Issuer:      "Tinyauth",
			AccountName: user.Username,
		})

		if keyErr != nil {
			log.Fatal().Err(keyErr).Msg("Failed to generate totp secret")
		}

		// Create secret
		secret := key.Secret()

		// Print secret and image
		log.Info().Str("secret", secret).Msg("Generated totp secret")

		// Print QR code
		log.Info().Msg("Generated QR code")

		config := qrterminal.Config{
			Level:     qrterminal.L,
			Writer:    os.Stdout,
			BlackChar: qrterminal.BLACK,
			WhiteChar: qrterminal.WHITE,
			QuietZone: 2,
		}

		qrterminal.GenerateWithConfig(key.URL(), config)

		// Add the secret to the user
		user.TotpSecret = secret

		// If using docker escape re-escape it
		if dockerEscape {
			user.Password = strings.ReplaceAll(user.Password, "$", "$$")
		}

		// Print success
		log.Info().Str("user", fmt.Sprintf("%s:%s:%s", user.Username, user.Password, user.TotpSecret)).Msg("Add the totp secret to your authenticator app then use the verify command to ensure everything is working correctly.")
	},
}

func init() {
	// Add interactive flag
	GenerateCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Run in interactive mode")
	GenerateCmd.Flags().StringVar(&iUser, "user", "", "Your current username:hash")
}
