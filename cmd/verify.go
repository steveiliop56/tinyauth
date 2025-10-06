package cmd

import (
	"errors"
	"strings"
	"tinyauth/internal/utils"

	"github.com/charmbracelet/huh"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

type verifyUserCmd struct {
	root *cobra.Command
	cmd  *cobra.Command

	interactive bool
	username    string
	password    string
	totp        string
	user        string
}

func newVerifyUserCmd(root *cobra.Command) *verifyUserCmd {
	return &verifyUserCmd{
		root: root,
	}
}

func (c *verifyUserCmd) Register() {
	c.cmd = &cobra.Command{
		Use:   "verify",
		Short: "Verify a user is set up correctly",
		Long:  `Verify a user is set up correctly meaning that it has a correct username, password and TOTP code.`,
		Run:   c.run,
	}

	c.cmd.Flags().BoolVarP(&c.interactive, "interactive", "i", false, "Create a user interactively")
	c.cmd.Flags().StringVar(&c.username, "username", "", "Username")
	c.cmd.Flags().StringVar(&c.password, "password", "", "Password")
	c.cmd.Flags().StringVar(&c.totp, "totp", "", "TOTP code")
	c.cmd.Flags().StringVar(&c.user, "user", "", "Hash (username:hash:totp)")

	if c.root != nil {
		c.root.AddCommand(c.cmd)
	}
}

func (c *verifyUserCmd) GetCmd() *cobra.Command {
	return c.cmd
}

func (c *verifyUserCmd) run(cmd *cobra.Command, args []string) {
	log.Logger = log.Level(zerolog.InfoLevel)

	if c.interactive {
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().Title("User (username:hash:totp)").Value(&c.user).Validate((func(s string) error {
					if s == "" {
						return errors.New("user cannot be empty")
					}
					return nil
				})),
				huh.NewInput().Title("Username").Value(&c.username).Validate((func(s string) error {
					if s == "" {
						return errors.New("username cannot be empty")
					}
					return nil
				})),
				huh.NewInput().Title("Password").Value(&c.password).Validate((func(s string) error {
					if s == "" {
						return errors.New("password cannot be empty")
					}
					return nil
				})),
				huh.NewInput().Title("TOTP Code (optional)").Value(&c.totp),
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

	if user.Username != c.username {
		log.Fatal().Msg("Username is incorrect")
	}

	var passwd string
	if strings.Contains(user.Password, "$$") {
		passwd = strings.ReplaceAll(user.Password, "$$", "$")
	} else {
		passwd = c.password
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(passwd))
	if err != nil {
		log.Fatal().Msg("Password is incorrect")
	}

	if user.TotpSecret == "" {
		if c.totp != "" {
			log.Warn().Msg("User does not have TOTP secret")
		}
		log.Info().Msg("User verified")
		return
	}

	ok := totp.Validate(c.totp, user.TotpSecret)
	if !ok {
		log.Fatal().Msg("TOTP code incorrect")

	}

	log.Info().Msg("User verified")
}
