package cmd

import (
	"os"
	"time"
	"tinyauth/internal/api"
	"tinyauth/internal/assets"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "tinyauth",
	Short: "An extremely simple traefik forward auth proxy.",
	Long: `Tinyauth is an extremely simple traefik forward-auth login screen that makes securing your apps easy.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Logger
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Timestamp().Logger()
		log.Info().Str("version", assets.Version).Msg("Starting tinyauth")

		// Get config
		log.Info().Msg("Parsing config")
		var config types.Config
		parseErr := viper.Unmarshal(&config)
		HandleError(parseErr, "Failed to parse config")

		// Validate config
		log.Info().Msg("Validating config")
		validator := validator.New()
		validateErr := validator.Struct(config)
		HandleError(validateErr, "Invalid config")

		// Create users list
		log.Info().Msg("Creating users list")
		userList, createErr := utils.CreateUsersList(config.Users)
		HandleError(createErr, "Failed to create users list")

		// Start server
		log.Info().Msg("Starting server")
		api.Run(config, userList)
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func HandleError(err error, msg string) {
	if err != nil {
		log.Fatal().Err(err).Msg(msg)
		os.Exit(1)
	}
}

func init() {
	viper.AutomaticEnv()
	rootCmd.Flags().IntP("port", "p", 3000, "Port to run the server on.")
	rootCmd.Flags().String("address", "0.0.0.0", "Address to bind the server to.")
	rootCmd.Flags().String("secret", "", "Secret to use for the cookie.")
	rootCmd.Flags().String("root-url", "", "Root URL of traefik.")
	rootCmd.Flags().String("app-url", "", "The tinyauth URL.")
	rootCmd.Flags().String("users", "", "Comma separated list of users in the format username:bcrypt-hashed-password.")
	viper.BindEnv("port", "PORT")
	viper.BindEnv("address", "ADDRESS")
	viper.BindEnv("secret", "SECRET")
	viper.BindEnv("root-url", "ROOT_URL")
	viper.BindEnv("app-url", "APP_URL")
	viper.BindEnv("users", "USERS")
	viper.BindPFlags(rootCmd.Flags())
}
