package api

import (
	"fmt"
	"io/fs"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"time"
	"tinyauth/internal/assets"
	"tinyauth/internal/auth"
	"tinyauth/internal/hooks"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/rs/zerolog/log"
)

func NewAPI(config types.APIConfig, hooks *hooks.Hooks, auth *auth.Auth, providers *providers.Providers) *API {
	return &API{
		Config:    config,
		Hooks:     hooks,
		Auth:      auth,
		Providers: providers,
	}
}

type API struct {
	Config    types.APIConfig
	Router    *gin.Engine
	Hooks     *hooks.Hooks
	Auth      *auth.Auth
	Providers *providers.Providers
	Domain    string
}

func (api *API) Init() {
	// Disable gin logs
	gin.SetMode(gin.ReleaseMode)

	// Create router and use zerolog for logs
	log.Debug().Msg("Setting up router")
	router := gin.New()
	router.Use(zerolog())

	// Read UI assets
	log.Debug().Msg("Setting up assets")
	dist, distErr := fs.Sub(assets.Assets, "dist")

	if distErr != nil {
		log.Fatal().Err(distErr).Msg("Failed to get UI assets")
	}

	// Create file server
	log.Debug().Msg("Setting up file server")
	fileServer := http.FileServer(http.FS(dist))

	// Setup cookie store
	log.Debug().Msg("Setting up cookie store")
	store := cookie.NewStore([]byte(api.Config.Secret))

	// Get domain to use for session cookies
	log.Debug().Msg("Getting domain")
	domain, domainErr := utils.GetRootURL(api.Config.AppURL)

	if domainErr != nil {
		log.Fatal().Err(domainErr).Msg("Failed to get domain")
		os.Exit(1)
	}

	log.Info().Str("domain", domain).Msg("Using domain for cookies")

	api.Domain = fmt.Sprintf(".%s", domain)

	// Use session middleware
	store.Options(sessions.Options{
		Domain:   api.Domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   api.Config.CookieSecure,
		MaxAge:   api.Config.SessionExpiry,
	})

	router.Use(sessions.Sessions("tinyauth", store))

	// UI middleware
	router.Use(func(c *gin.Context) {
		// If not an API request, serve the UI
		if !strings.HasPrefix(c.Request.URL.Path, "/api") {
			_, err := fs.Stat(dist, strings.TrimPrefix(c.Request.URL.Path, "/"))

			// If the file doesn't exist, serve the index.html
			if os.IsNotExist(err) {
				c.Request.URL.Path = "/"
			}

			// Serve the file
			fileServer.ServeHTTP(c.Writer, c.Request)

			// Stop further processing
			c.Abort()
		}
	})

	// Set router
	api.Router = router
}

func (api *API) SetupRoutes() {
	api.Router.GET("/api/auth/:proxy", func(c *gin.Context) {
		// Create struct for proxy
		var proxy types.Proxy

		// Bind URI
		bindErr := c.BindUri(&proxy)

		// Handle error
		if bindErr != nil {
			log.Error().Err(bindErr).Msg("Failed to bind URI")
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Bad Request",
			})
			return
		}

		log.Debug().Interface("proxy", proxy.Proxy).Msg("Got proxy")

		// Get user context
		userContext := api.Hooks.UseUserContext(c)

		// Check if using basic auth
		_, _, basicAuth := c.Request.BasicAuth()

		// Get headers
		uri := c.Request.Header.Get("X-Forwarded-Uri")
		proto := c.Request.Header.Get("X-Forwarded-Proto")
		host := c.Request.Header.Get("X-Forwarded-Host")

		// Check if user is logged in
		if userContext.IsLoggedIn {
			log.Debug().Msg("Authenticated")

			// Check if user is allowed to access subdomain, if request is nginx.example.com the subdomain (resource) is nginx
			appAllowed, appAllowedErr := api.Auth.ResourceAllowed(userContext, host)

			// Check if there was an error
			if appAllowedErr != nil {
				// Return 501 if nginx is the proxy or if the request is using basic auth
				if proxy.Proxy == "nginx" || basicAuth {
					log.Error().Err(appAllowedErr).Msg("Failed to check if app is allowed")
					c.JSON(501, gin.H{
						"status":  501,
						"message": "Internal Server Error",
					})
					return
				}

				// Return the internal server error page
				if api.handleError(c, "Failed to check if app is allowed", appAllowedErr) {
					return
				}
			}

			log.Debug().Bool("appAllowed", appAllowed).Msg("Checking if app is allowed")

			// The user is not allowed to access the app
			if !appAllowed {
				log.Warn().Str("username", userContext.Username).Str("host", host).Msg("User not allowed")

				// Return 401 if nginx is the proxy or if the request is using an Authorization header
				if proxy.Proxy == "nginx" || basicAuth {
					c.Header("WWW-Authenticate", "Basic realm=\"tinyauth\"")
					c.JSON(401, gin.H{
						"status":  401,
						"message": "Unauthorized",
					})
					return
				}

				// Build query
				queries, queryErr := query.Values(types.UnauthorizedQuery{
					Username: userContext.Username,
					Resource: strings.Split(host, ".")[0],
				})

				// Handle error (no need to check for nginx/headers since we are sure we are using caddy/traefik)
				if api.handleError(c, "Failed to build query", queryErr) {
					return
				}

				// We are using caddy/traefik so redirect
				c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", api.Config.AppURL, queries.Encode()))

				// Stop further processing
				return
			}

			// The user is allowed to access the app
			c.JSON(200, gin.H{
				"status":  200,
				"message": "Authenticated",
			})

			// Stop further processing
			return
		}

		// The user is not logged in
		log.Debug().Msg("Unauthorized")

		// Return 401 if nginx is the proxy or if the request is using an Authorization header
		if proxy.Proxy == "nginx" || basicAuth {
			c.Header("WWW-Authenticate", "Basic realm=\"tinyauth\"")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}

		// Build query
		queries, queryErr := query.Values(types.LoginQuery{
			RedirectURI: fmt.Sprintf("%s://%s%s", proto, host, uri),
		})

		// Handle error (no need to check for nginx/headers since we are sure we are using caddy/traefik)
		if api.handleError(c, "Failed to build query", queryErr) {
			return
		}

		log.Debug().Interface("redirect_uri", fmt.Sprintf("%s://%s%s", proto, host, uri)).Msg("Redirecting to login")

		// Redirect to login
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/?%s", api.Config.AppURL, queries.Encode()))
	})

	api.Router.POST("/api/login", func(c *gin.Context) {
		// Create login struct
		var login types.LoginRequest

		// Bind JSON
		err := c.BindJSON(&login)

		// Handle error
		if err != nil {
			log.Error().Err(err).Msg("Failed to bind JSON")
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Bad Request",
			})
			return
		}

		log.Debug().Msg("Got login request")

		// Get user based on username
		user := api.Auth.GetUser(login.Username)

		// User does not exist
		if user == nil {
			log.Debug().Str("username", login.Username).Msg("User not found")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}

		log.Debug().Msg("Got user")

		// Check if password is correct
		if !api.Auth.CheckPassword(*user, login.Password) {
			log.Debug().Str("username", login.Username).Msg("Password incorrect")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}

		log.Debug().Msg("Password correct, logging in")

		// Create session cookie with username as provider
		api.Auth.CreateSessionCookie(c, &types.SessionCookie{
			Username: login.Username,
			Provider: "username",
		})

		// Return logged in
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Logged in",
		})
	})

	api.Router.POST("/api/logout", func(c *gin.Context) {
		log.Debug().Msg("Logging out")

		// Delete session cookie
		api.Auth.DeleteSessionCookie(c)

		log.Debug().Msg("Cleaning up redirect cookie")

		// Clean up redirect cookie if it exists
		c.SetCookie("tinyauth_redirect_uri", "", -1, "/", api.Domain, api.Config.CookieSecure, true)

		// Return logged out
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Logged out",
		})
	})

	api.Router.GET("/api/status", func(c *gin.Context) {
		log.Debug().Msg("Checking status")

		// Get user context
		userContext := api.Hooks.UseUserContext(c)

		// Get configured providers
		configuredProviders := api.Providers.GetConfiguredProviders()

		// We have username/password configured so add it to our providers
		if api.Auth.UserAuthConfigured() {
			configuredProviders = append(configuredProviders, "username")
		}

		// Fill status struct with data from user context and api config
		status := types.Status{
			Username:            userContext.Username,
			IsLoggedIn:          userContext.IsLoggedIn,
			Oauth:               userContext.OAuth,
			Provider:            userContext.Provider,
			ConfiguredProviders: configuredProviders,
			DisableContinue:     api.Config.DisableContinue,
			Title:               api.Config.Title,
			GenericName:         api.Config.GenericName,
		}

		// If we are not logged in we set the status to 401 and add the WWW-Authenticate header else we set it to 200
		if !userContext.IsLoggedIn {
			log.Debug().Msg("Unauthorized")
			c.Header("WWW-Authenticate", "Basic realm=\"tinyauth\"")
			status.Status = 401
			status.Message = "Unauthorized"
		} else {
			log.Debug().Interface("userContext", userContext).Strs("configuredProviders", configuredProviders).Bool("disableContinue", api.Config.DisableContinue).Msg("Authenticated")
			status.Status = 200
			status.Message = "Authenticated"
		}

		// // Marshall status to JSON
		// statusJson, marshalErr := json.Marshal(status)

		// // Handle error
		// if marshalErr != nil {
		// 	log.Error().Err(marshalErr).Msg("Failed to marshal status")
		// 	c.JSON(500, gin.H{
		// 		"status":  500,
		// 		"message": "Internal Server Error",
		// 	})
		// 	return
		// }

		// Return data
		c.JSON(200, status)
	})

	api.Router.GET("/api/oauth/url/:provider", func(c *gin.Context) {
		// Create struct for OAuth request
		var request types.OAuthRequest

		// Bind URI
		bindErr := c.BindUri(&request)

		// Handle error
		if bindErr != nil {
			log.Error().Err(bindErr).Msg("Failed to bind URI")
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Bad Request",
			})
			return
		}

		log.Debug().Msg("Got OAuth request")

		// Check if provider exists
		provider := api.Providers.GetProvider(request.Provider)

		// Provider does not exist
		if provider == nil {
			c.JSON(404, gin.H{
				"status":  404,
				"message": "Not Found",
			})
			return
		}

		log.Debug().Str("provider", request.Provider).Msg("Got provider")

		// Get auth URL
		authURL := provider.GetAuthURL()

		log.Debug().Msg("Got auth URL")

		// Get redirect URI
		redirectURI := c.Query("redirect_uri")

		// Set redirect cookie if redirect URI is provided
		if redirectURI != "" {
			log.Debug().Str("redirectURI", redirectURI).Msg("Setting redirect cookie")
			c.SetCookie("tinyauth_redirect_uri", redirectURI, 3600, "/", api.Domain, api.Config.CookieSecure, true)
		}

		// Tailscale does not have an auth url so we create a random code (does not need to be secure) to avoid caching and send it
		if request.Provider == "tailscale" {
			// Build tailscale query
			tailscaleQuery, tailscaleQueryErr := query.Values(types.TailscaleQuery{
				Code: (1000 + rand.IntN(9000)),
			})

			// Handle error
			if tailscaleQueryErr != nil {
				log.Error().Err(tailscaleQueryErr).Msg("Failed to build query")
				c.JSON(500, gin.H{
					"status":  500,
					"message": "Internal Server Error",
				})
				return
			}

			// Return tailscale URL (immidiately redirects to the callback)
			c.JSON(200, gin.H{
				"status":  200,
				"message": "Ok",
				"url":     fmt.Sprintf("%s/api/oauth/callback/tailscale?%s", api.Config.AppURL, tailscaleQuery.Encode()),
			})
			return
		}

		// Return auth URL
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Ok",
			"url":     authURL,
		})
	})

	api.Router.GET("/api/oauth/callback/:provider", func(c *gin.Context) {
		// Create struct for OAuth request
		var providerName types.OAuthRequest

		// Bind URI
		bindErr := c.BindUri(&providerName)

		// Handle error
		if api.handleError(c, "Failed to bind URI", bindErr) {
			return
		}

		log.Debug().Interface("provider", providerName.Provider).Msg("Got provider name")

		// Get code
		code := c.Query("code")

		// Code empty so redirect to error
		if code == "" {
			log.Error().Msg("No code provided")
			c.Redirect(http.StatusPermanentRedirect, "/error")
			return
		}

		log.Debug().Msg("Got code")

		// Get provider
		provider := api.Providers.GetProvider(providerName.Provider)

		log.Debug().Str("provider", providerName.Provider).Msg("Got provider")

		// Provider does not exist
		if provider == nil {
			c.Redirect(http.StatusPermanentRedirect, "/not-found")
			return
		}

		// Exchange token (authenticates user)
		_, tokenErr := provider.ExchangeToken(code)

		log.Debug().Msg("Got token")

		// Handle error
		if api.handleError(c, "Failed to exchange token", tokenErr) {
			return
		}

		// Get email
		email, emailErr := api.Providers.GetUser(providerName.Provider)

		log.Debug().Str("email", email).Msg("Got email")

		// Handle error
		if api.handleError(c, "Failed to get user", emailErr) {
			return
		}

		// Email is not whitelisted
		if !api.Auth.EmailWhitelisted(email) {
			log.Warn().Str("email", email).Msg("Email not whitelisted")

			// Build query
			unauthorizedQuery, unauthorizedQueryErr := query.Values(types.UnauthorizedQuery{
				Username: email,
			})

			// Handle error
			if api.handleError(c, "Failed to build query", unauthorizedQueryErr) {
				return
			}

			// Redirect to unauthorized
			c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/unauthorized?%s", api.Config.AppURL, unauthorizedQuery.Encode()))
		}

		log.Debug().Msg("Email whitelisted")

		// Create session cookie
		api.Auth.CreateSessionCookie(c, &types.SessionCookie{
			Username: email,
			Provider: providerName.Provider,
		})

		// Get redirect URI
		redirectURI, redirectURIErr := c.Cookie("tinyauth_redirect_uri")

		// If it is empty it means that no redirect_uri was provided to the login screen so we just log in
		if redirectURIErr != nil {
			c.Redirect(http.StatusPermanentRedirect, api.Config.AppURL)
		}

		log.Debug().Str("redirectURI", redirectURI).Msg("Got redirect URI")

		// Clean up redirect cookie since we already have the value
		c.SetCookie("tinyauth_redirect_uri", "", -1, "/", api.Domain, api.Config.CookieSecure, true)

		// Build query
		redirectQuery, redirectQueryErr := query.Values(types.LoginQuery{
			RedirectURI: redirectURI,
		})

		log.Debug().Msg("Got redirect query")

		// Handle error
		if api.handleError(c, "Failed to build query", redirectQueryErr) {
			return
		}

		// Redirect to continue with the redirect URI
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/continue?%s", api.Config.AppURL, redirectQuery.Encode()))
	})

	// Simple healthcheck
	api.Router.GET("/api/healthcheck", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  200,
			"message": "OK",
		})
	})
}

func (api *API) Run() {
	log.Info().Str("address", api.Config.Address).Int("port", api.Config.Port).Msg("Starting server")

	// Run server
	api.Router.Run(fmt.Sprintf("%s:%d", api.Config.Address, api.Config.Port))
}

// handleError logs the error and redirects to the error page (only meant for stuff the user may access does not apply for login paths)
func (api *API) handleError(c *gin.Context, msg string, err error) bool {
	// If error is not nil log it and redirect to error page also return true so we can stop further processing
	if err != nil {
		log.Error().Err(err).Msg(msg)
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", api.Config.AppURL))
		return true
	}
	return false
}

// zerolog is a middleware for gin that logs requests using zerolog
func zerolog() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get initial time
		tStart := time.Now()

		// Process request
		c.Next()

		// Get status code, address, method and path
		code := c.Writer.Status()
		address := c.Request.RemoteAddr
		method := c.Request.Method
		path := c.Request.URL.Path

		// Get latency
		latency := time.Since(tStart).String()

		// Log request
		switch {
		case code >= 200 && code < 300:
			log.Info().Str("method", method).Str("path", path).Str("address", address).Int("status", code).Str("latency", latency).Msg("Request")
		case code >= 300 && code < 400:
			log.Warn().Str("method", method).Str("path", path).Str("address", address).Int("status", code).Str("latency", latency).Msg("Request")
		case code >= 400:
			log.Error().Str("method", method).Str("path", path).Str("address", address).Int("status", code).Str("latency", latency).Msg("Request")
		}
	}
}
