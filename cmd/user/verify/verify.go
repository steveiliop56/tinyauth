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
		log.Logger = log.Level(zerolog.InfoLevel)

		if interactive {
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

		if user.Username != iUsername {
			log.Fatal().Msg("Username is incorrect")
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(iPassword))
		if err != nil {
			log.Fatal().Msg("Password is incorrect")
		}

		if user.TotpSecret == "" {
			if iTotp != "" {
				log.Warn().Msg("User does not have 2fa secret")
			}
			log.Info().Msg("User verified")
			return
		}

		ok := totp.Validate(iTotp, user.TotpSecret)
		if !ok {
			log.Fatal().Msg("Totp code incorrect")

		}

		log.Info().Msg("User verified")
	},
}

func init() {
	VerifyCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Create a user interactively")
	VerifyCmd.Flags().BoolVar(&docker, "docker", false, "Is the user formatted for docker?")
	VerifyCmd.Flags().StringVar(&iUsername, "username", "", "Username")
	VerifyCmd.Flags().StringVar(&iPassword, "password", "", "Password")
	VerifyCmd.Flags().StringVar(&iTotp, "totp", "", "Totp code")
	VerifyCmd.Flags().StringVar(&iUser, "user", "", "Hash (username:hash:totp combination)")
}
