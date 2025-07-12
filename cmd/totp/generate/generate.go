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

var interactive bool

// Input user
var iUser string

var GenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a totp secret",
	Run: func(cmd *cobra.Command, args []string) {
		log.Logger = log.Level(zerolog.InfoLevel)

		if interactive {
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
			var baseTheme *huh.Theme = huh.ThemeBase()
			err := form.WithTheme(baseTheme).Run()
			if err != nil {
				log.Fatal().Err(err).Msg("Form failed")
			}
		}

		user, err := utils.ParseUser(iUser)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to parse user")
		}

		dockerEscape := false
		if strings.Contains(iUser, "$$") {
			dockerEscape = true
		}

		if user.TotpSecret != "" {
			log.Fatal().Msg("User already has a totp secret")
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "Tinyauth",
			AccountName: user.Username,
		})
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to generate totp secret")
		}

		secret := key.Secret()

		log.Info().Str("secret", secret).Msg("Generated totp secret")

		log.Info().Msg("Generated QR code")

		config := qrterminal.Config{
			Level:     qrterminal.L,
			Writer:    os.Stdout,
			BlackChar: qrterminal.BLACK,
			WhiteChar: qrterminal.WHITE,
			QuietZone: 2,
		}

		qrterminal.GenerateWithConfig(key.URL(), config)

		user.TotpSecret = secret

		// If using docker escape re-escape it
		if dockerEscape {
			user.Password = strings.ReplaceAll(user.Password, "$", "$$")
		}

		log.Info().Str("user", fmt.Sprintf("%s:%s:%s", user.Username, user.Password, user.TotpSecret)).Msg("Add the totp secret to your authenticator app then use the verify command to ensure everything is working correctly.")
	},
}

func init() {
	GenerateCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Run in interactive mode")
	GenerateCmd.Flags().StringVar(&iUser, "user", "", "Your current username:hash")
}
