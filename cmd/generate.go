package cmd

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

type generateTotpCmd struct {
	root *cobra.Command
	cmd  *cobra.Command

	interactive bool
	user        string
}

func newGenerateTotpCmd(root *cobra.Command) *generateTotpCmd {
	return &generateTotpCmd{
		root: root,
	}
}

func (c *generateTotpCmd) Register() {
	c.cmd = &cobra.Command{
		Use:   "generate",
		Short: "Generate a totp secret",
		Long:  `Generate a totp secret for a user either interactively or by passing flags.`,
		Run:   c.run,
	}

	c.cmd.Flags().BoolVarP(&c.interactive, "interactive", "i", false, "Run in interactive mode")
	c.cmd.Flags().StringVar(&c.user, "user", "", "Your current user (username:hash)")

	if c.root != nil {
		c.root.AddCommand(c.cmd)
	}
}

func (c *generateTotpCmd) GetCmd() *cobra.Command {
	return c.cmd
}

func (c *generateTotpCmd) run(cmd *cobra.Command, args []string) {
	log.Logger = log.Level(zerolog.InfoLevel)

	if c.interactive {
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().Title("Current user (username:hash)").Value(&c.user).Validate((func(s string) error {
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

	user, err := utils.ParseUser(c.user)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse user")
	}

	docker := false
	if strings.Contains(c.user, "$$") {
		docker = true
	}

	if user.TotpSecret != "" {
		log.Fatal().Msg("User already has a TOTP secret")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Tinyauth",
		AccountName: user.Username,
	})

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to generate TOTP secret")
	}

	secret := key.Secret()

	log.Info().Str("secret", secret).Msg("Generated TOTP secret")

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
	if docker {
		user.Password = strings.ReplaceAll(user.Password, "$", "$$")
	}

	log.Info().Str("user", fmt.Sprintf("%s:%s:%s", user.Username, user.Password, user.TotpSecret)).Msg("Add the totp secret to your authenticator app then use the verify command to ensure everything is working correctly.")
}
