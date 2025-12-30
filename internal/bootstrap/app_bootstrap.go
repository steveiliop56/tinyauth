package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/controller"
	"github.com/steveiliop56/tinyauth/internal/repository"
	"github.com/steveiliop56/tinyauth/internal/utils"

	"github.com/rs/zerolog/log"
)

type BootstrapApp struct {
	config  config.Config
	context struct {
		uuid                string
		cookieDomain        string
		sessionCookieName   string
		csrfCookieName      string
		redirectCookieName  string
		users               []config.User
		oauthProviders      map[string]config.OAuthServiceConfig
		configuredProviders []controller.Provider
	}
	services Services
}

func NewBootstrapApp(config config.Config) *BootstrapApp {
	return &BootstrapApp{
		config: config,
	}
}

func (app *BootstrapApp) Setup() error {
	// Parse users
	users, err := utils.GetUsers(app.config.Auth.Users, app.config.Auth.UsersFile)

	if err != nil {
		return err
	}

	app.context.users = users

	// Setup OAuth providers
	app.context.oauthProviders = app.config.OAuth.Providers

	for name, provider := range app.context.oauthProviders {
		secret := utils.GetSecret(provider.ClientSecret, provider.ClientSecretFile)
		provider.ClientSecret = secret
		provider.ClientSecretFile = ""
		app.context.oauthProviders[name] = provider
	}

	for id := range config.OverrideProviders {
		if provider, exists := app.context.oauthProviders[id]; exists {
			if provider.RedirectURL == "" {
				provider.RedirectURL = app.config.AppURL + "/api/oauth/callback/" + id
				app.context.oauthProviders[id] = provider
			}
		}
	}

	for id, provider := range app.context.oauthProviders {
		if provider.Name == "" {
			if name, ok := config.OverrideProviders[id]; ok {
				provider.Name = name
			} else {
				provider.Name = utils.Capitalize(id)
			}
		}
		app.context.oauthProviders[id] = provider
	}

	// Get cookie domain
	cookieDomain, err := utils.GetCookieDomain(app.config.AppURL)

	if err != nil {
		return err
	}

	app.context.cookieDomain = cookieDomain

	// Cookie names
	appUrl, _ := url.Parse(app.config.AppURL) // Already validated
	app.context.uuid = utils.GenerateUUID(appUrl.Hostname())
	cookieId := strings.Split(app.context.uuid, "-")[0]
	app.context.sessionCookieName = fmt.Sprintf("%s-%s", config.SessionCookieName, cookieId)
	app.context.csrfCookieName = fmt.Sprintf("%s-%s", config.CSRFCookieName, cookieId)
	app.context.redirectCookieName = fmt.Sprintf("%s-%s", config.RedirectCookieName, cookieId)

	// Dumps
	log.Trace().Interface("config", app.config).Msg("Config dump")
	log.Trace().Interface("users", app.context.users).Msg("Users dump")
	log.Trace().Interface("oauthProviders", app.context.oauthProviders).Msg("OAuth providers dump")
	log.Trace().Str("cookieDomain", app.context.cookieDomain).Msg("Cookie domain")
	log.Trace().Str("sessionCookieName", app.context.sessionCookieName).Msg("Session cookie name")
	log.Trace().Str("csrfCookieName", app.context.csrfCookieName).Msg("CSRF cookie name")
	log.Trace().Str("redirectCookieName", app.context.redirectCookieName).Msg("Redirect cookie name")

	// Database
	db, err := app.setupDatabase(app.config.DatabasePath)

	if err != nil {
		return fmt.Errorf("failed to setup database: %w", err)
	}

	// Queries
	queries := repository.New(db)

	// Services
	services, err := app.initServices(queries)

	if err != nil {
		return fmt.Errorf("failed to initialize services: %w", err)
	}

	app.services = services

	// Configured providers
	configuredProviders := make([]controller.Provider, 0)

	for id, provider := range app.context.oauthProviders {
		configuredProviders = append(configuredProviders, controller.Provider{
			Name:  provider.Name,
			ID:    id,
			OAuth: true,
		})
	}

	sort.Slice(configuredProviders, func(i, j int) bool {
		return configuredProviders[i].Name < configuredProviders[j].Name
	})

	if services.authService.UserAuthConfigured() {
		configuredProviders = append(configuredProviders, controller.Provider{
			Name:  "Username",
			ID:    "username",
			OAuth: false,
		})
	}

	log.Debug().Interface("providers", configuredProviders).Msg("Authentication providers")

	if len(configuredProviders) == 0 {
		return fmt.Errorf("no authentication providers configured")
	}

	app.context.configuredProviders = configuredProviders

	// Setup router
	router, err := app.setupRouter()

	if err != nil {
		return fmt.Errorf("failed to setup routes: %w", err)
	}

	// Start db cleanup routine
	log.Debug().Msg("Starting database cleanup routine")
	go app.dbCleanup(queries)

	// If analytics are not disabled, start heartbeat
	if !app.config.DisableAnalytics {
		log.Debug().Msg("Starting heartbeat routine")
		go app.heartbeat()
	}

	// If we have an socket path, bind to it
	if app.config.Server.SocketPath != "" {
		if _, err := os.Stat(app.config.Server.SocketPath); err == nil {
			log.Info().Msgf("Removing existing socket file %s", app.config.Server.SocketPath)
			err := os.Remove(app.config.Server.SocketPath)
			if err != nil {
				return fmt.Errorf("failed to remove existing socket file: %w", err)
			}
		}

		log.Info().Msgf("Starting server on unix socket %s", app.config.Server.SocketPath)
		if err := router.RunUnix(app.config.Server.SocketPath); err != nil {
			log.Fatal().Err(err).Msg("Failed to start server")
		}

		return nil
	}

	// Start server
	address := fmt.Sprintf("%s:%d", app.config.Server.Address, app.config.Server.Port)
	log.Info().Msgf("Starting server on %s", address)
	if err := router.Run(address); err != nil {
		log.Fatal().Err(err).Msg("Failed to start server")
	}

	return nil
}

func (app *BootstrapApp) heartbeat() {
	ticker := time.NewTicker(time.Duration(12) * time.Hour)
	defer ticker.Stop()

	type heartbeat struct {
		UUID    string `json:"uuid"`
		Version string `json:"version"`
	}

	var body heartbeat

	body.UUID = app.context.uuid
	body.Version = config.Version

	bodyJson, err := json.Marshal(body)

	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal heartbeat body")
		return
	}

	client := &http.Client{
		Timeout: 30 * time.Second, // The server should never take more than 30 seconds to respond
	}

	heartbeatURL := config.ApiServer + "/v1/instances/heartbeat"

	for ; true; <-ticker.C {
		log.Debug().Msg("Sending heartbeat")

		req, err := http.NewRequest(http.MethodPost, heartbeatURL, bytes.NewReader(bodyJson))

		if err != nil {
			log.Error().Err(err).Msg("Failed to create heartbeat request")
			continue
		}

		req.Header.Add("Content-Type", "application/json")

		res, err := client.Do(req)

		if err != nil {
			log.Error().Err(err).Msg("Failed to send heartbeat")
			continue
		}

		res.Body.Close()

		if res.StatusCode != 200 && res.StatusCode != 201 {
			log.Debug().Str("status", res.Status).Msg("Heartbeat returned non-200/201 status")
		}
	}
}

func (app *BootstrapApp) dbCleanup(queries *repository.Queries) {
	ticker := time.NewTicker(time.Duration(30) * time.Minute)
	defer ticker.Stop()
	ctx := context.Background()

	for ; true; <-ticker.C {
		log.Debug().Msg("Cleaning up old database sessions")
		err := queries.DeleteExpiredSessions(ctx, time.Now().Unix())
		if err != nil {
			log.Error().Err(err).Msg("Failed to clean up old database sessions")
		}
	}
}
