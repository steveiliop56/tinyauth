package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

type createUserCmd struct {
	root *cobra.Command
	cmd  *cobra.Command

	interactive bool
	docker      bool
	username    string
	password    string
}

func newCreateUserCmd(root *cobra.Command) *createUserCmd {
	return &createUserCmd{
		root: root,
	}
}

func (c *createUserCmd) Register() {
	c.cmd = &cobra.Command{
		Use:   "create",
		Short: "Create a user",
		Long:  `Create a user either interactively or by passing flags.`,
		Run:   c.run,
	}

	c.cmd.Flags().BoolVarP(&c.interactive, "interactive", "i", false, "Create a user interactively")
	c.cmd.Flags().BoolVar(&c.docker, "docker", false, "Format output for docker")
	c.cmd.Flags().StringVar(&c.username, "username", "", "Username")
	c.cmd.Flags().StringVar(&c.password, "password", "", "Password")

	if c.root != nil {
		c.root.AddCommand(c.cmd)
	}
}

func (c *createUserCmd) GetCmd() *cobra.Command {
	return c.cmd
}

func (c *createUserCmd) run(cmd *cobra.Command, args []string) {
	log.Logger = log.Level(zerolog.InfoLevel)

	if c.interactive {
		form := huh.NewForm(
			huh.NewGroup(
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
				huh.NewSelect[bool]().Title("Format the output for Docker?").Options(huh.NewOption("Yes", true), huh.NewOption("No", false)).Value(&c.docker),
			),
		)
		var baseTheme *huh.Theme = huh.ThemeBase()
		err := form.WithTheme(baseTheme).Run()
		if err != nil {
			log.Fatal().Err(err).Msg("Form failed")
		}
	}

	if c.username == "" || c.password == "" {
		log.Fatal().Err(errors.New("error invalid input")).Msg("Username and password cannot be empty")
	}

	log.Info().Str("username", c.username).Msg("Creating user")

	passwd, err := bcrypt.GenerateFromPassword([]byte(c.password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to hash password")
	}

	// If docker format is enabled, escape the dollar sign
	passwdStr := string(passwd)
	if c.docker {
		passwdStr = strings.ReplaceAll(passwdStr, "$", "$$")
	}

	log.Info().Str("user", fmt.Sprintf("%s:%s", c.username, passwdStr)).Msg("User created")
}
