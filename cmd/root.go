package cmd

import (
	"errors"
	"os"
	"strings"
	"time"
	totpCmd "tinyauth/cmd/totp"
	userCmd "tinyauth/cmd/user"
	"tinyauth/internal/api"
	"tinyauth/internal/assets"
	"tinyauth/internal/auth"
	"tinyauth/internal/docker"
	"tinyauth/internal/handlers"
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
		// Logger
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Timestamp().Logger().Level(zerolog.FatalLevel)

		// Get config
		var config types.Config
		err := viper.Unmarshal(&config)
		HandleError(err, "Failed to parse config")

		// Secrets
		config.Secret = utils.GetSecret(config.Secret, config.SecretFile)
		config.GithubClientSecret = utils.GetSecret(config.GithubClientSecret, config.GithubClientSecretFile)
		config.GoogleClientSecret = utils.GetSecret(config.GoogleClientSecret, config.GoogleClientSecretFile)
		config.GenericClientSecret = utils.GetSecret(config.GenericClientSecret, config.GenericClientSecretFile)

		// Validate config
		validator := validator.New()
		err = validator.Struct(config)
		HandleError(err, "Failed to validate config")

		// Logger
		log.Logger = log.Level(zerolog.Level(config.LogLevel))
		log.Info().Str("version", assets.Version).Msg("Starting tinyauth")

		// Users
		log.Info().Msg("Parsing users")
		users, err := utils.GetUsers(config.Users, config.UsersFile)
		HandleError(err, "Failed to parse users")

		if len(users) == 0 && !utils.OAuthConfigured(config) {
			HandleError(errors.New("no users or OAuth configured"), "No users or OAuth configured")
		}

		// Get domain
		log.Debug().Msg("Getting domain")
		domain, err := utils.GetUpperDomain(config.AppURL)
		HandleError(err, "Failed to get upper domain")
		log.Info().Str("domain", domain).Msg("Using domain for cookie store")

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

		// Create handlers config
		handlersConfig := types.HandlersConfig{
			AppURL:                config.AppURL,
			DisableContinue:       config.DisableContinue,
			Title:                 config.Title,
			GenericName:           config.GenericName,
			CookieSecure:          config.CookieSecure,
			Domain:                domain,
			ForgotPasswordMessage: config.FogotPasswordMessage,
		}

		// Create api config
		apiConfig := types.APIConfig{
			Port:    config.Port,
			Address: config.Address,
		}

		// Create auth config
		authConfig := types.AuthConfig{
			Users:           users,
			OauthWhitelist:  config.OAuthWhitelist,
			Secret:          config.Secret,
			CookieSecure:    config.CookieSecure,
			SessionExpiry:   config.SessionExpiry,
			Domain:          domain,
			LoginTimeout:    config.LoginTimeout,
			LoginMaxRetries: config.LoginMaxRetries,
		}

		// Create docker service
		docker := docker.NewDocker()

		// Initialize docker
		err = docker.Init()
		HandleError(err, "Failed to initialize docker")

		// Create auth service
		auth := auth.NewAuth(authConfig, docker)

		// Create OAuth providers service
		providers := providers.NewProviders(oauthConfig)

		// Initialize providers
		providers.Init()

		// Create hooks service
		hooks := hooks.NewHooks(auth, providers)

		// Create handlers
		handlers := handlers.NewHandlers(handlersConfig, auth, hooks, providers, docker)

		// Create API
		api := api.NewAPI(apiConfig, handlers)

		// Setup routes
		api.Init()
		api.SetupRoutes()

		// Start
		api.Run()
	},
}

func Execute() {
	err := rootCmd.Execute()
	HandleError(err, "Failed to execute root command")
}

func HandleError(err error, msg string) {
	// If error, log it and exit
	if err != nil {
		log.Fatal().Err(err).Msg(msg)
	}
}

func init() {
	// Add user command
	rootCmd.AddCommand(userCmd.UserCmd())

	// Add totp command
	rootCmd.AddCommand(totpCmd.TotpCmd())

	// Read environment variables
	viper.AutomaticEnv()

	// Flags
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
	rootCmd.Flags().String("generic-name", "Generic", "Generic OAuth provider name.")
	rootCmd.Flags().Bool("disable-continue", false, "Disable continue screen and redirect to app directly.")
	rootCmd.Flags().String("oauth-whitelist", "", "Comma separated list of email addresses to whitelist when using OAuth.")
	rootCmd.Flags().Int("session-expiry", 86400, "Session (cookie) expiration time in seconds.")
	rootCmd.Flags().Int("login-timeout", 300, "Login timeout in seconds after max retries reached (0 to disable).")
	rootCmd.Flags().Int("login-max-retries", 5, "Maximum login attempts before timeout (0 to disable).")
	rootCmd.Flags().Int("log-level", 1, "Log level.")
	rootCmd.Flags().String("app-title", "Tinyauth", "Title of the app.")
	rootCmd.Flags().String("forgot-password-message", "You can reset your password by changing the `USERS` environment variable.", "Message to show on the forgot password page.")

	// Bind flags to environment
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
	viper.BindEnv("generic-name", "GENERIC_NAME")
	viper.BindEnv("disable-continue", "DISABLE_CONTINUE")
	viper.BindEnv("oauth-whitelist", "OAUTH_WHITELIST")
	viper.BindEnv("session-expiry", "SESSION_EXPIRY")
	viper.BindEnv("log-level", "LOG_LEVEL")
	viper.BindEnv("app-title", "APP_TITLE")
	viper.BindEnv("login-timeout", "LOGIN_TIMEOUT")
	viper.BindEnv("login-max-retries", "LOGIN_MAX_RETRIES")
	viper.BindEnv("forgot-password-message", "FORGOT_PASSWORD_MESSAGE")

	// Bind flags to viper
	viper.BindPFlags(rootCmd.Flags())
}
