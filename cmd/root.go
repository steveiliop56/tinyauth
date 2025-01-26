package cmd

import (
	"strings"
	cmd "tinyauth/cmd/user"
	"tinyauth/internal/api"
	"tinyauth/internal/auth"
	"tinyauth/internal/hooks"
	"tinyauth/internal/providers"
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
	Short: "The simplest way to protect your apps with a login screen.",
	Long:  `Tinyauth is a simple authentication middleware that adds simple username/password login or OAuth with Google, Github and any generic OAuth provider to all of your docker apps.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Get config
		log.Info().Msg("Parsing config")
		var config types.Config
		parseErr := viper.Unmarshal(&config)
		HandleError(parseErr, "Failed to parse config")

		// Secrets
		log.Info().Msg("Parsing secrets")

		config.Secret = utils.GetSecret(config.Secret, config.SecretFile)
		config.GithubClientSecret = utils.GetSecret(config.GithubClientSecret, config.GithubClientSecretFile)
		config.GoogleClientSecret = utils.GetSecret(config.GoogleClientSecret, config.GoogleClientSecretFile)
		config.GenericClientSecret = utils.GetSecret(config.GenericClientSecret, config.GenericClientSecretFile)

		// Validate config
		log.Info().Msg("Validating config")
		validator := validator.New()
		validateErr := validator.Struct(config)
		HandleError(validateErr, "Invalid config")

		// Set log level
		log.Info().Int8("log_level", config.LogLevel).Msg("Setting log level")
		log.Logger = log.Logger.Level(zerolog.Level(config.LogLevel))

		// Users
		log.Info().Msg("Parsing users")
		users, usersErr := utils.GetUsers(config.Users, config.UsersFile)

		if (len(users) == 0 || usersErr != nil) && !utils.OAuthConfigured(config) {
			log.Fatal().Err(usersErr).Msg("Failed to parse users")
		}

		// Create oauth whitelist
		oauthWhitelist := strings.Split(config.OAuthWhitelist, ",")
		log.Debug().Strs("oauth_whitelist", oauthWhitelist).Msg("Parsed OAuth whitelist")

		// Create OAuth config
		oauthConfig := types.OAuthConfig{
			GithubClientId:      config.GithubClientId,
			GithubClientSecret:  config.GithubClientSecret,
			GoogleClientId:      config.GoogleClientId,
			GoogleClientSecret:  config.GoogleClientSecret,
			GenericClientId:     config.GenericClientId,
			GenericClientSecret: config.GenericClientSecret,
			GenericScopes:       strings.Split(config.GenericScopes, ","),
			GenericAuthURL:      config.GenericAuthURL,
			GenericTokenURL:     config.GenericTokenURL,
			GenericUserURL:      config.GenericUserURL,
			AppURL:              config.AppURL,
		}
		log.Debug().Interface("oauth_config", oauthConfig).Msg("Parsed OAuth config")

		// Create auth service
		auth := auth.NewAuth(users, oauthWhitelist)

		// Create OAuth providers service
		providers := providers.NewProviders(oauthConfig)

		// Initialize providers
		providers.Init()

		// Create hooks service
		hooks := hooks.NewHooks(auth, providers)

		// Create API
		api := api.NewAPI(types.APIConfig{
			Port:            config.Port,
			Address:         config.Address,
			Secret:          config.Secret,
			AppURL:          config.AppURL,
			CookieSecure:    config.CookieSecure,
			DisableContinue: config.DisableContinue,
			CookieExpiry:    config.CookieExpiry,
		}, hooks, auth, providers)

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
		log.Fatal().Err(err).Msg("Failed to execute command")
	}
}

func HandleError(err error, msg string) {
	if err != nil {
		log.Fatal().Err(err).Msg(msg)
	}
}

func init() {
	rootCmd.AddCommand(cmd.UserCmd())
	viper.AutomaticEnv()
	rootCmd.Flags().Int("port", 3000, "Port to run the server on.")
	rootCmd.Flags().String("address", "0.0.0.0", "Address to bind the server to.")
	rootCmd.Flags().String("secret", "", "Secret to use for the cookie.")
	rootCmd.Flags().String("secret-file", "", "Path to a file containing the secret.")
	rootCmd.Flags().String("app-url", "", "The tinyauth URL.")
	rootCmd.Flags().String("users", "", "Comma separated list of users in the format username:hash.")
	rootCmd.Flags().String("users-file", "", "Path to a file containing users in the format username:hash.")
	rootCmd.Flags().Bool("cookie-secure", false, "Send cookie over secure connection only.")
	rootCmd.Flags().String("github-client-id", "", "Github OAuth client ID.")
	rootCmd.Flags().String("github-client-secret", "", "Github OAuth client secret.")
	rootCmd.Flags().String("github-client-secret-file", "", "Github OAuth client secret file.")
	rootCmd.Flags().String("google-client-id", "", "Google OAuth client ID.")
	rootCmd.Flags().String("google-client-secret", "", "Google OAuth client secret.")
	rootCmd.Flags().String("google-client-secret-file", "", "Google OAuth client secret file.")
	rootCmd.Flags().String("generic-client-id", "", "Generic OAuth client ID.")
	rootCmd.Flags().String("generic-client-secret", "", "Generic OAuth client secret.")
	rootCmd.Flags().String("generic-client-secret-file", "", "Generic OAuth client secret file.")
	rootCmd.Flags().String("generic-scopes", "", "Generic OAuth scopes.")
	rootCmd.Flags().String("generic-auth-url", "", "Generic OAuth auth URL.")
	rootCmd.Flags().String("generic-token-url", "", "Generic OAuth token URL.")
	rootCmd.Flags().String("generic-user-url", "", "Generic OAuth user info URL.")
	rootCmd.Flags().Bool("disable-continue", false, "Disable continue screen and redirect to app directly.")
	rootCmd.Flags().String("oauth-whitelist", "", "Comma separated list of email addresses to whitelist when using OAuth.")
	rootCmd.Flags().Int("cookie-expiry", 86400, "Cookie expiration time in seconds.")
	rootCmd.Flags().Int("log-level", 1, "Log level.")
	viper.BindEnv("port", "PORT")
	viper.BindEnv("address", "ADDRESS")
	viper.BindEnv("secret", "SECRET")
	viper.BindEnv("secret-file", "SECRET_FILE")
	viper.BindEnv("app-url", "APP_URL")
	viper.BindEnv("users", "USERS")
	viper.BindEnv("users-file", "USERS_FILE")
	viper.BindEnv("cookie-secure", "COOKIE_SECURE")
	viper.BindEnv("github-client-id", "GITHUB_CLIENT_ID")
	viper.BindEnv("github-client-secret", "GITHUB_CLIENT_SECRET")
	viper.BindEnv("github-client-secret-file", "GITHUB_CLIENT_SECRET_FILE")
	viper.BindEnv("google-client-id", "GOOGLE_CLIENT_ID")
	viper.BindEnv("google-client-secret", "GOOGLE_CLIENT_SECRET")
	viper.BindEnv("google-client-secret-file", "GOOGLE_CLIENT_SECRET_FILE")
	viper.BindEnv("generic-client-id", "GENERIC_CLIENT_ID")
	viper.BindEnv("generic-client-secret", "GENERIC_CLIENT_SECRET")
	viper.BindEnv("generic-client-secret-file", "GENERIC_CLIENT_SECRET_FILE")
	viper.BindEnv("generic-scopes", "GENERIC_SCOPES")
	viper.BindEnv("generic-auth-url", "GENERIC_AUTH_URL")
	viper.BindEnv("generic-token-url", "GENERIC_TOKEN_URL")
	viper.BindEnv("generic-user-url", "GENERIC_USER_URL")
	viper.BindEnv("disable-continue", "DISABLE_CONTINUE")
	viper.BindEnv("oauth-whitelist", "OAUTH_WHITELIST")
	viper.BindEnv("cookie-expiry", "COOKIE_EXPIRY")
	viper.BindEnv("log-level", "LOG_LEVEL")
	viper.BindPFlags(rootCmd.Flags())
}
