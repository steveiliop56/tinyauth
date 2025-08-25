package cmd

import (
	"errors"
	"fmt"
	"strings"
	totpCmd "tinyauth/cmd/totp"
	userCmd "tinyauth/cmd/user"
	"tinyauth/internal/auth"
	"tinyauth/internal/constants"
	"tinyauth/internal/docker"
	"tinyauth/internal/handlers"
	"tinyauth/internal/ldap"
	"tinyauth/internal/middleware"
	"tinyauth/internal/providers"
	"tinyauth/internal/server"
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
		var config types.Config
		err := viper.Unmarshal(&config)
		HandleError(err, "Failed to parse config")

		// Check if secrets have a file associated with them
		config.Secret = utils.GetSecret(config.Secret, config.SecretFile)
		config.GithubClientSecret = utils.GetSecret(config.GithubClientSecret, config.GithubClientSecretFile)
		config.GoogleClientSecret = utils.GetSecret(config.GoogleClientSecret, config.GoogleClientSecretFile)
		config.GenericClientSecret = utils.GetSecret(config.GenericClientSecret, config.GenericClientSecretFile)

		validator := validator.New()
		err = validator.Struct(config)
		HandleError(err, "Failed to validate config")

		log.Logger = log.Level(zerolog.Level(config.LogLevel))
		log.Info().Str("version", strings.TrimSpace(constants.Version)).Msg("Starting tinyauth")

		log.Info().Msg("Parsing users")
		users, err := utils.GetUsers(config.Users, config.UsersFile)
		HandleError(err, "Failed to parse users")

		log.Debug().Msg("Getting domain")
		domain, err := utils.GetUpperDomain(config.AppURL)
		HandleError(err, "Failed to get upper domain")
		log.Info().Str("domain", domain).Msg("Using domain for cookie store")

		cookieId := utils.GenerateIdentifier(strings.Split(domain, ".")[0])
		sessionCookieName := fmt.Sprintf("%s-%s", constants.SessionCookieName, cookieId)
		csrfCookieName := fmt.Sprintf("%s-%s", constants.CsrfCookieName, cookieId)
		redirectCookieName := fmt.Sprintf("%s-%s", constants.RedirectCookieName, cookieId)

		log.Debug().Msg("Deriving HMAC and encryption secrets")

		hmacSecret, err := utils.DeriveKey(config.Secret, "hmac")
		HandleError(err, "Failed to derive HMAC secret")

		encryptionSecret, err := utils.DeriveKey(config.Secret, "encryption")
		HandleError(err, "Failed to derive encryption secret")

		// Split the config into service-specific sub-configs
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
			GenericSkipSSL:      config.GenericSkipSSL,
			AppURL:              config.AppURL,
		}

		handlersConfig := handlers.HandlersConfig{
			AppURL:                config.AppURL,
			DisableContinue:       config.DisableContinue,
			Title:                 config.Title,
			GenericName:           config.GenericName,
			CookieSecure:          config.CookieSecure,
			Domain:                domain,
			ForgotPasswordMessage: config.FogotPasswordMessage,
			BackgroundImage:       config.BackgroundImage,
			OAuthAutoRedirect:     config.OAuthAutoRedirect,
			CsrfCookieName:        csrfCookieName,
			RedirectCookieName:    redirectCookieName,
		}

		serverConfig := types.ServerConfig{
			Port:    config.Port,
			Address: config.Address,
		}

		authConfig := types.AuthConfig{
			Users:             users,
			OauthWhitelist:    config.OAuthWhitelist,
			CookieSecure:      config.CookieSecure,
			SessionExpiry:     config.SessionExpiry,
			Domain:            domain,
			LoginTimeout:      config.LoginTimeout,
			LoginMaxRetries:   config.LoginMaxRetries,
			SessionCookieName: sessionCookieName,
			HMACSecret:        hmacSecret,
			EncryptionSecret:  encryptionSecret,
		}

		var ldapService *ldap.LDAP

		if config.LdapAddress != "" {
			log.Info().Msg("Using LDAP for authentication")
			ldapConfig := types.LdapConfig{
				Address:      config.LdapAddress,
				BindDN:       config.LdapBindDN,
				BindPassword: config.LdapBindPassword,
				BaseDN:       config.LdapBaseDN,
				Insecure:     config.LdapInsecure,
				SearchFilter: config.LdapSearchFilter,
			}
			ldapService, err = ldap.NewLDAP(ldapConfig)
			if err != nil {
				log.Error().Err(err).Msg("Failed to initialize LDAP service, disabling LDAP authentication")
				ldapService = nil
			}
		} else {
			log.Info().Msg("LDAP not configured, using local users or OAuth")
		}

		// Check if we have a source of users
		if len(users) == 0 && !utils.OAuthConfigured(config) && ldapService == nil {
			HandleError(errors.New("err no users"), "Unable to find a source of users")
		}

		// Setup the services
		docker, err := docker.NewDocker()
		HandleError(err, "Failed to initialize docker")
		auth := auth.NewAuth(authConfig, docker, ldapService)
		providers := providers.NewProviders(oauthConfig)
		handlers := handlers.NewHandlers(handlersConfig, auth, providers, docker)

		// Setup the middlewares
		var middlewares []server.Middleware

		contextMiddleware := middleware.NewContextMiddleware(middleware.ContextMiddlewareConfig{
			Domain: domain,
		}, auth, providers)
		uiMiddleware := middleware.NewUIMiddleware()
		zerologMiddleware := middleware.NewZerologMiddleware()

		middlewares = append(middlewares, contextMiddleware, uiMiddleware, zerologMiddleware)

		srv, err := server.NewServer(serverConfig, handlers, middlewares)
		HandleError(err, "Failed to create server")

		// Start up
		err = srv.Start()
		HandleError(err, "Failed to start server")
	},
}

func Execute() {
	err := rootCmd.Execute()
	HandleError(err, "Failed to execute root command")
}

func HandleError(err error, msg string) {
	if err != nil {
		log.Fatal().Err(err).Msg(msg)
	}
}

func init() {
	rootCmd.AddCommand(userCmd.UserCmd())
	rootCmd.AddCommand(totpCmd.TotpCmd())

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
	rootCmd.Flags().String("generic-name", "Generic", "Generic OAuth provider name.")
	rootCmd.Flags().Bool("generic-skip-ssl", false, "Skip SSL verification for the generic OAuth provider.")
	rootCmd.Flags().Bool("disable-continue", false, "Disable continue screen and redirect to app directly.")
	rootCmd.Flags().String("oauth-whitelist", "", "Comma separated list of email addresses to whitelist when using OAuth.")
	rootCmd.Flags().String("oauth-auto-redirect", "none", "Auto redirect to the specified OAuth provider if configured. (available providers: github, google, generic)")
	rootCmd.Flags().Int("session-expiry", 86400, "Session (cookie) expiration time in seconds.")
	rootCmd.Flags().Int("login-timeout", 300, "Login timeout in seconds after max retries reached (0 to disable).")
	rootCmd.Flags().Int("login-max-retries", 5, "Maximum login attempts before timeout (0 to disable).")
	rootCmd.Flags().Int("log-level", 1, "Log level.")
	rootCmd.Flags().String("app-title", "Tinyauth", "Title of the app.")
	rootCmd.Flags().String("forgot-password-message", "", "Message to show on the forgot password page.")
	rootCmd.Flags().String("background-image", "/background.jpg", "Background image URL for the login page.")
	rootCmd.Flags().String("ldap-address", "", "LDAP server address (e.g. ldap://localhost:389).")
	rootCmd.Flags().String("ldap-bind-dn", "", "LDAP bind DN (e.g. uid=user,dc=example,dc=com).")
	rootCmd.Flags().String("ldap-bind-password", "", "LDAP bind password.")
	rootCmd.Flags().String("ldap-base-dn", "", "LDAP base DN (e.g. dc=example,dc=com).")
	rootCmd.Flags().Bool("ldap-insecure", false, "Skip certificate verification for the LDAP server.")
	rootCmd.Flags().String("ldap-search-filter", "(uid=%s)", "LDAP search filter for user lookup.")

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
	viper.BindEnv("generic-skip-ssl", "GENERIC_SKIP_SSL")
	viper.BindEnv("disable-continue", "DISABLE_CONTINUE")
	viper.BindEnv("oauth-whitelist", "OAUTH_WHITELIST")
	viper.BindEnv("oauth-auto-redirect", "OAUTH_AUTO_REDIRECT")
	viper.BindEnv("session-expiry", "SESSION_EXPIRY")
	viper.BindEnv("log-level", "LOG_LEVEL")
	viper.BindEnv("app-title", "APP_TITLE")
	viper.BindEnv("login-timeout", "LOGIN_TIMEOUT")
	viper.BindEnv("login-max-retries", "LOGIN_MAX_RETRIES")
	viper.BindEnv("forgot-password-message", "FORGOT_PASSWORD_MESSAGE")
	viper.BindEnv("background-image", "BACKGROUND_IMAGE")
	viper.BindEnv("ldap-address", "LDAP_ADDRESS")
	viper.BindEnv("ldap-bind-dn", "LDAP_BIND_DN")
	viper.BindEnv("ldap-bind-password", "LDAP_BIND_PASSWORD")
	viper.BindEnv("ldap-base-dn", "LDAP_BASE_DN")
	viper.BindEnv("ldap-insecure", "LDAP_INSECURE")
	viper.BindEnv("ldap-search-filter", "LDAP_SEARCH_FILTER")

	viper.BindPFlags(rootCmd.Flags())
}
