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

var GenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a totp secret",
	Run: func(cmd *cobra.Command, args []string) {
		// Setup logger
		log.Logger = log.Level(zerolog.InfoLevel)

		// Variables
		var userStr string
		var totpCode string

		// Use simple theme
		var baseTheme *huh.Theme = huh.ThemeBase()

		// Create huh form
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().Title("User (username:hash)").Value(&userStr).Validate((func(s string) error {
					if s == "" {
						return errors.New("user cannot be empty")
					}
					return nil
				})),
			),
		)

		formErr := form.WithTheme(baseTheme).Run()

		if formErr != nil {
			log.Fatal().Err(formErr).Msg("Form failed")
		}

		// Remove double dollar signs
		userStr = strings.ReplaceAll(userStr, "$$", "$")

		log.Info().Str("user", userStr).Msg("User")

		// Parse user
		user, parseErr := utils.ParseUser(userStr)

		if parseErr != nil {
			log.Fatal().Err(parseErr).Msg("Failed to parse user")
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

		// Wait for verify
		log.Info().Msg("Scan the QR code with your authenticator app then press enter to verify")

		// Wait for enter
		var input string
		_, _ = fmt.Scanln(&input)

		// Move cursor up and overwrite the line
		fmt.Print("\033[F\033[K")

		// Create huh form
		form = huh.NewForm(
			huh.NewGroup(
				huh.NewInput().Title("Code").Value(&totpCode).Validate((func(s string) error {
					if s == "" {
						return errors.New("code cannot be empty")
					}
					return nil
				})),
			),
		)

		formErr = form.WithTheme(baseTheme).Run()

		if formErr != nil {
			log.Fatal().Err(formErr).Msg("Form failed")
		}

		// Verify code
		codeOk := totp.Validate(totpCode, secret)

		if !codeOk {
			log.Fatal().Msg("Failed to verify code")
		}

		// Update user
		user.TotpSecret = secret

		// Print success
		log.Info().Str("user", fmt.Sprintf("%s:%s:%s", user.Username, user.Password, user.TotpSecret)).Msg("Code verified, get your new user")
	},
}

func init() {
}
