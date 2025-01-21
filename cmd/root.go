package cmd

import (
	"os"
	"strings"
	"time"
	"tinyauth/internal/api"
	"tinyauth/internal/assets"
	"tinyauth/internal/auth"
	"tinyauth/internal/hooks"
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

		// Parse users
		log.Info().Msg("Parsing users")

		if config.UsersFile == "" && config.Users == "" {
			log.Fatal().Msg("No users provided")
			os.Exit(1)
		}

		usersString := config.Users

		if config.UsersFile != "" {
			log.Info().Msg("Reading users from file")
			usersFromFile, readErr := utils.GetUsersFromFile(config.UsersFile)
			HandleError(readErr, "Failed to read users from file")
			usersFromFileParsed := strings.Join(strings.Split(usersFromFile, "\n"), ",")
			if usersString != "" {
				usersString = usersString + "," + usersFromFileParsed
			} else {
				usersString = usersFromFileParsed
			}
		}

		users, parseErr := utils.ParseUsers(usersString)
		HandleError(parseErr, "Failed to parse users")

		// Create auth service
		auth := auth.NewAuth(users)
		
		// Create hooks service
		hooks := hooks.NewHooks(auth)
		
		// Create API
		api := api.NewAPI(types.APIConfig{
			Port: config.Port,
			Address: config.Address,
			Secret: config.Secret,
			AppURL: config.AppURL,
			CookieSecure: config.CookieSecure,
		}, hooks, auth)

		// Setup routes
		api.Init()
		api.SetupRoutes()

		// Start
		api.Run()
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
	rootCmd.Flags().String("app-url", "", "The tinyauth URL.")
	rootCmd.Flags().String("users", "", "Comma separated list of users in the format username:bcrypt-hashed-password.")
	rootCmd.Flags().String("users-file", "", "Path to a file containing users in the format username:bcrypt-hashed-password.")
	viper.BindEnv("port", "PORT")
	viper.BindEnv("address", "ADDRESS")
	viper.BindEnv("secret", "SECRET")
	viper.BindEnv("app-url", "APP_URL")
	viper.BindEnv("users", "USERS")
	viper.BindEnv("users-file", "USERS_FILE")
	viper.BindPFlags(rootCmd.Flags())
}
