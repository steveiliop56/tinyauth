package create

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

var interactive bool
var docker bool

// i stands for input
var iUsername string
var iPassword string

var CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a user",
	Long:  `Create a user either interactively or by passing flags.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Setup logger
		log.Logger = log.Level(zerolog.InfoLevel)

		// Check if interactive
		if interactive {
			// Create huh form
			form := huh.NewForm(
				huh.NewGroup(
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
					huh.NewSelect[bool]().Title("Format the output for docker?").Options(huh.NewOption("Yes", true), huh.NewOption("No", false)).Value(&docker),
				),
			)

			// Use simple theme
			var baseTheme *huh.Theme = huh.ThemeBase()

			formErr := form.WithTheme(baseTheme).Run()

			if formErr != nil {
				log.Fatal().Err(formErr).Msg("Form failed")
			}
		}

		// Do we have username and password?
		if iUsername == "" || iPassword == "" {
			log.Error().Msg("Username and password cannot be empty")
		}

		log.Info().Str("username", iUsername).Str("password", iPassword).Bool("docker", docker).Msg("Creating user")

		// Hash password
		password, passwordErr := bcrypt.GenerateFromPassword([]byte(iPassword), bcrypt.DefaultCost)

		if passwordErr != nil {
			log.Fatal().Err(passwordErr).Msg("Failed to hash password")
		}

		// Convert password to string
		passwordString := string(password)

		// Escape $ for docker
		if docker {
			passwordString = strings.ReplaceAll(passwordString, "$", "$$")
		}

		// Log user created
		log.Info().Str("user", fmt.Sprintf("%s:%s", iUsername, passwordString)).Msg("User created")
	},
}

func init() {
	// Flags
	CreateCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Create a user interactively")
	CreateCmd.Flags().BoolVar(&docker, "docker", false, "Format output for docker")
	CreateCmd.Flags().StringVar(&iUsername, "username", "", "Username")
	CreateCmd.Flags().StringVar(&iPassword, "password", "", "Password")
}
