package cmd

import (
	"strings"
	totpCmd "tinyauth/cmd/totp"
	userCmd "tinyauth/cmd/user"
	"tinyauth/internal/bootstrap"
	"tinyauth/internal/config"
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
		var conf config.Config

		err := viper.Unmarshal(&conf)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to parse config")
		}

		// Validate config
		v := validator.New()

		err = v.Struct(conf)
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
	rootCmd.FParseErrWhitelist.UnknownFlags = true
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
		{"app-url", "", "The Tinyauth URL."},
		{"users", "", "Comma separated list of users in the format username:hash."},
		{"users-file", "", "Path to a file containing users in the format username:hash."},
		{"secure-cookie", false, "Send cookie over secure connection only."},
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
		{"resources-dir", "/data/resources", "Path to a directory containing custom resources (e.g. background image)."},
		{"database-path", "/data/tinyauth.db", "Path to the Sqlite database file."},
		{"trusted-proxies", "", "Comma separated list of trusted proxies (IP addresses or CIDRs) for correct client IP detection."},
		{"disable-analytics", false, "Disable anonymous version collection."},
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
