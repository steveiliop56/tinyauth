package cmd

import (
	"strings"
	totpCmd "tinyauth/cmd/totp"
	userCmd "tinyauth/cmd/user"
	"tinyauth/internal/bootstrap"
	"tinyauth/internal/config"
	"tinyauth/internal/utils"

	"github.com/go-playground/validator"
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
		var conf config.Config

		err := viper.Unmarshal(&conf)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to parse config")
		}

		// Check if secrets have a file associated with them
		conf.Secret = utils.GetSecret(conf.Secret, conf.SecretFile)
		conf.GithubClientSecret = utils.GetSecret(conf.GithubClientSecret, conf.GithubClientSecretFile)
		conf.GoogleClientSecret = utils.GetSecret(conf.GoogleClientSecret, conf.GoogleClientSecretFile)
		conf.GenericClientSecret = utils.GetSecret(conf.GenericClientSecret, conf.GenericClientSecretFile)

		validator := validator.New()

		err = validator.Struct(conf)
		if err != nil {
			log.Fatal().Err(err).Msg("Invalid config")
		}

		log.Logger = log.Level(zerolog.Level(utils.GetLogLevel(conf.LogLevel)))
		log.Info().Str("version", strings.TrimSpace(config.Version)).Msg("Starting tinyauth")

		// Create bootstrap app
		app := bootstrap.NewBootstrapApp(conf)

		// Run
		err = app.Setup()

		if err != nil {
			log.Fatal().Err(err).Msg("Failed to setup app")
		}

	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to execute command")
	}
}

func init() {
	rootCmd.AddCommand(userCmd.UserCmd())
	rootCmd.AddCommand(totpCmd.TotpCmd())

	viper.AutomaticEnv()

	configOptions := []struct {
		name        string
		defaultVal  any
		description string
	}{
		{"port", 3000, "Port to run the server on."},
		{"address", "0.0.0.0", "Address to bind the server to."},
		{"secret", "", "Secret to use for the cookie."},
		{"secret-file", "", "Path to a file containing the secret."},
		{"app-url", "", "The Tinyauth URL."},
		{"users", "", "Comma separated list of users in the format username:hash."},
		{"users-file", "", "Path to a file containing users in the format username:hash."},
		{"cookie-secure", false, "Send cookie over secure connection only."},
		{"github-client-id", "", "Github OAuth client ID."},
		{"github-client-secret", "", "Github OAuth client secret."},
		{"github-client-secret-file", "", "Github OAuth client secret file."},
		{"google-client-id", "", "Google OAuth client ID."},
		{"google-client-secret", "", "Google OAuth client secret."},
		{"google-client-secret-file", "", "Google OAuth client secret file."},
		{"generic-client-id", "", "Generic OAuth client ID."},
		{"generic-client-secret", "", "Generic OAuth client secret."},
		{"generic-client-secret-file", "", "Generic OAuth client secret file."},
		{"generic-scopes", "", "Generic OAuth scopes."},
		{"generic-auth-url", "", "Generic OAuth auth URL."},
		{"generic-token-url", "", "Generic OAuth token URL."},
		{"generic-user-url", "", "Generic OAuth user info URL."},
		{"generic-name", "Generic", "Generic OAuth provider name."},
		{"generic-skip-ssl", false, "Skip SSL verification for the generic OAuth provider."},
		{"disable-continue", false, "Disable continue screen and redirect to app directly."},
		{"oauth-whitelist", "", "Comma separated list of email addresses to whitelist when using OAuth."},
		{"oauth-auto-redirect", "none", "Auto redirect to the specified OAuth provider if configured. (available providers: github, google, generic)"},
		{"session-expiry", 86400, "Session (cookie) expiration time in seconds."},
		{"login-timeout", 300, "Login timeout in seconds after max retries reached (0 to disable)."},
		{"login-max-retries", 5, "Maximum login attempts before timeout (0 to disable)."},
		{"log-level", "info", "Log level."},
		{"app-title", "Tinyauth", "Title of the app."},
		{"forgot-password-message", "", "Message to show on the forgot password page."},
		{"background-image", "/background.jpg", "Background image URL for the login page."},
		{"ldap-address", "", "LDAP server address (e.g. ldap://localhost:389)."},
		{"ldap-bind-dn", "", "LDAP bind DN (e.g. uid=user,dc=example,dc=com)."},
		{"ldap-bind-password", "", "LDAP bind password."},
		{"ldap-base-dn", "", "LDAP base DN (e.g. dc=example,dc=com)."},
		{"ldap-insecure", false, "Skip certificate verification for the LDAP server."},
		{"ldap-search-filter", "(uid=%s)", "LDAP search filter for user lookup."},
	}

	for _, opt := range configOptions {
		switch v := opt.defaultVal.(type) {
		case bool:
			rootCmd.Flags().Bool(opt.name, v, opt.description)
		case int:
			rootCmd.Flags().Int(opt.name, v, opt.description)
		case string:
			rootCmd.Flags().String(opt.name, v, opt.description)
		}

		// Create uppercase env var name
		envVar := strings.ReplaceAll(strings.ToUpper(opt.name), "-", "_")
		viper.BindEnv(opt.name, envVar)
	}

	viper.BindPFlags(rootCmd.Flags())
}
