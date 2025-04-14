package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"tinyauth/internal/auth"
	"tinyauth/internal/docker"
	"tinyauth/internal/hooks"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
)

func NewHandlers(config types.HandlersConfig, auth *auth.Auth, hooks *hooks.Hooks, providers *providers.Providers, docker *docker.Docker) *Handlers {
	return &Handlers{
		Config:    config,
		Auth:      auth,
		Hooks:     hooks,
		Providers: providers,
		Docker:    docker,
	}
}

type Handlers struct {
	Config    types.HandlersConfig
	Auth      *auth.Auth
	Hooks     *hooks.Hooks
	Providers *providers.Providers
	Docker    *docker.Docker
}

func (h *Handlers) AuthHandler(c *gin.Context) {
	// Create struct for proxy
	var proxy types.Proxy

	// Bind URI
	err := c.BindUri(&proxy)

	// Handle error
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	// Check if the request is coming from a browser (tools like curl/bruno use */* and they don't include the text/html)
	isBrowser := strings.Contains(c.Request.Header.Get("Accept"), "text/html")

	if isBrowser {
		log.Debug().Msg("Request is most likely coming from a browser")
	} else {
		log.Debug().Msg("Request is most likely not coming from a browser")
	}

	log.Debug().Interface("proxy", proxy.Proxy).Msg("Got proxy")

	// Get headers
	uri := c.Request.Header.Get("X-Forwarded-Uri")
	proto := c.Request.Header.Get("X-Forwarded-Proto")
	host := c.Request.Header.Get("X-Forwarded-Host")

	// Check if auth is enabled
	authEnabled, err := h.Auth.AuthEnabled(c)

	// Check if there was an error
	if err != nil {
		log.Error().Err(err).Msg("Failed to check if app is allowed")

		if proxy.Proxy == "nginx" || !isBrowser {
			c.JSON(500, gin.H{
				"status":  500,
				"message": "Internal Server Error",
			})
			return
		}

		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	// Get the app id
	appId := strings.Split(host, ".")[0]

	// Get the container labels
	labels, err := h.Docker.GetLabels(appId)

	// Check if there was an error
	if err != nil {
		log.Error().Err(err).Msg("Failed to check if app is allowed")

		if proxy.Proxy == "nginx" || !isBrowser {
			c.JSON(500, gin.H{
				"status":  500,
				"message": "Internal Server Error",
			})
			return
		}

		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	// If auth is not enabled, return 200
	if !authEnabled {
		for key, value := range labels.Headers {
			log.Debug().Str("key", key).Str("value", value).Msg("Setting header")
			c.Header(key, value)
		}
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	// Get user context
	userContext := h.Hooks.UseUserContext(c)

	// Check if user is logged in
	if userContext.IsLoggedIn {
		log.Debug().Msg("Authenticated")

		// Check if user is allowed to access subdomain, if request is nginx.example.com the subdomain (resource) is nginx
		appAllowed, err := h.Auth.ResourceAllowed(c, userContext)

		// Check if there was an error
		if err != nil {
			log.Error().Err(err).Msg("Failed to check if app is allowed")

			if proxy.Proxy == "nginx" || !isBrowser {
				c.JSON(500, gin.H{
					"status":  500,
					"message": "Internal Server Error",
				})
				return
			}

			c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
			return
		}

		log.Debug().Bool("appAllowed", appAllowed).Msg("Checking if app is allowed")

		// The user is not allowed to access the app
		if !appAllowed {
			log.Warn().Str("username", userContext.Username).Str("host", host).Msg("User not allowed")

			// Set WWW-Authenticate header
			c.Header("WWW-Authenticate", "Basic realm=\"tinyauth\"")

			if proxy.Proxy == "nginx" || !isBrowser {
				c.JSON(401, gin.H{
					"status":  401,
					"message": "Unauthorized",
				})
				return
			}

			// Build query
			queries, err := query.Values(types.UnauthorizedQuery{
				Username: userContext.Username,
				Resource: strings.Split(host, ".")[0],
			})

			// Handle error (no need to check for nginx/headers since we are sure we are using caddy/traefik)
			if err != nil {
				log.Error().Err(err).Msg("Failed to build queries")
				c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
				return
			}

			// We are using caddy/traefik so redirect
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
			return
		}

		// Set the user header
		c.Header("Remote-User", userContext.Username)

		// Set the rest of the headers
		for key, value := range labels.Headers {
			log.Debug().Str("key", key).Str("value", value).Msg("Setting header")
			c.Header(key, value)
		}

		// The user is allowed to access the app
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	// The user is not logged in
	log.Debug().Msg("Unauthorized")

	// Set www-authenticate header
	c.Header("WWW-Authenticate", "Basic realm=\"tinyauth\"")

	if proxy.Proxy == "nginx" || !isBrowser {
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	queries, err := query.Values(types.LoginQuery{
		RedirectURI: fmt.Sprintf("%s://%s%s", proto, host, uri),
	})

	if err != nil {
		log.Error().Err(err).Msg("Failed to build queries")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	log.Debug().Interface("redirect_uri", fmt.Sprintf("%s://%s%s", proto, host, uri)).Msg("Redirecting to login")

	// Redirect to login
	c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/?%s", h.Config.AppURL, queries.Encode()))
}

func (h *Handlers) LoginHandler(c *gin.Context) {
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

	// Get client IP for rate limiting
	clientIP := c.ClientIP()

	// Create an identifier for rate limiting (username or IP if username doesn't exist yet)
	rateIdentifier := login.Username
	if rateIdentifier == "" {
		rateIdentifier = clientIP
	}

	// Check if the account is locked due to too many failed attempts
	locked, remainingTime := h.Auth.IsAccountLocked(rateIdentifier)
	if locked {
		log.Warn().Str("identifier", rateIdentifier).Int("remaining_seconds", remainingTime).Msg("Account is locked due to too many failed login attempts")
		c.JSON(429, gin.H{
			"status":  429,
			"message": fmt.Sprintf("Too many failed login attempts. Try again in %d seconds", remainingTime),
		})
		return
	}

	// Get user based on username
	user := h.Auth.GetUser(login.Username)

	// User does not exist
	if user == nil {
		log.Debug().Str("username", login.Username).Msg("User not found")
		// Record failed login attempt
		h.Auth.RecordLoginAttempt(rateIdentifier, false)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	log.Debug().Msg("Got user")

	// Check if password is correct
	if !h.Auth.CheckPassword(*user, login.Password) {
		log.Debug().Str("username", login.Username).Msg("Password incorrect")
		// Record failed login attempt
		h.Auth.RecordLoginAttempt(rateIdentifier, false)
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	log.Debug().Msg("Password correct, checking totp")

	// Record successful login attempt (will reset failed attempt counter)
	h.Auth.RecordLoginAttempt(rateIdentifier, true)

	// Check if user has totp enabled
	if user.TotpSecret != "" {
		log.Debug().Msg("Totp enabled")

		// Set totp pending cookie
		h.Auth.CreateSessionCookie(c, &types.SessionCookie{
			Username:    login.Username,
			Provider:    "username",
			TotpPending: true,
		})

		// Return totp required
		c.JSON(200, gin.H{
			"status":      200,
			"message":     "Waiting for totp",
			"totpPending": true,
		})

		// Stop further processing
		return
	}

	// Create session cookie with username as provider
	h.Auth.CreateSessionCookie(c, &types.SessionCookie{
		Username: login.Username,
		Provider: "username",
	})

	// Return logged in
	c.JSON(200, gin.H{
		"status":      200,
		"message":     "Logged in",
		"totpPending": false,
	})
}

func (h *Handlers) TotpHandler(c *gin.Context) {
	// Create totp struct
	var totpReq types.TotpRequest

	// Bind JSON
	err := c.BindJSON(&totpReq)

	// Handle error
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind JSON")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	log.Debug().Msg("Checking totp")

	// Get user context
	userContext := h.Hooks.UseUserContext(c)

	// Check if we have a user
	if userContext.Username == "" {
		log.Debug().Msg("No user context")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	// Get user
	user := h.Auth.GetUser(userContext.Username)

	// Check if user exists
	if user == nil {
		log.Debug().Msg("User not found")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	// Check if totp is correct
	ok := totp.Validate(totpReq.Code, user.TotpSecret)

	// TOTP is incorrect
	if !ok {
		log.Debug().Msg("Totp incorrect")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	log.Debug().Msg("Totp correct")

	// Create session cookie with username as provider
	h.Auth.CreateSessionCookie(c, &types.SessionCookie{
		Username: user.Username,
		Provider: "username",
	})

	// Return logged in
	c.JSON(200, gin.H{
		"status":  200,
		"message": "Logged in",
	})
}

func (h *Handlers) LogoutHandler(c *gin.Context) {
	log.Debug().Msg("Logging out")

	// Delete session cookie
	h.Auth.DeleteSessionCookie(c)

	log.Debug().Msg("Cleaning up redirect cookie")

	// Return logged out
	c.JSON(200, gin.H{
		"status":  200,
		"message": "Logged out",
	})
}

func (h *Handlers) AppHandler(c *gin.Context) {
	log.Debug().Msg("Getting app context")

	// Get configured providers
	configuredProviders := h.Providers.GetConfiguredProviders()

	// We have username/password configured so add it to our providers
	if h.Auth.UserAuthConfigured() {
		configuredProviders = append(configuredProviders, "username")
	}

	// Create app context struct
	appContext := types.AppContext{
		Status:              200,
		Message:             "OK",
		ConfiguredProviders: configuredProviders,
		DisableContinue:     h.Config.DisableContinue,
		Title:               h.Config.Title,
		GenericName:         h.Config.GenericName,
	}

	// Return app context
	c.JSON(200, appContext)
}

func (h *Handlers) UserHandler(c *gin.Context) {
	log.Debug().Msg("Getting user context")

	// Get user context
	userContext := h.Hooks.UseUserContext(c)

	// Create user context response
	userContextResponse := types.UserContextResponse{
		Status:      200,
		IsLoggedIn:  userContext.IsLoggedIn,
		Username:    userContext.Username,
		Provider:    userContext.Provider,
		Oauth:       userContext.OAuth,
		TotpPending: userContext.TotpPending,
	}

	// If we are not logged in we set the status to 401 and add the WWW-Authenticate header else we set it to 200
	if !userContext.IsLoggedIn {
		log.Debug().Msg("Unauthorized")
		c.Header("WWW-Authenticate", "Basic realm=\"tinyauth\"")
		userContextResponse.Message = "Unauthorized"
	} else {
		log.Debug().Interface("userContext", userContext).Msg("Authenticated")
		userContextResponse.Message = "Authenticated"
	}

	// Return user context
	c.JSON(200, userContextResponse)
}

func (h *Handlers) OauthUrlHandler(c *gin.Context) {
	// Create struct for OAuth request
	var request types.OAuthRequest

	// Bind URI
	err := c.BindUri(&request)

	// Handle error
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	log.Debug().Msg("Got OAuth request")

	// Check if provider exists
	provider := h.Providers.GetProvider(request.Provider)

	// Provider does not exist
	if provider == nil {
		c.JSON(404, gin.H{
			"status":  404,
			"message": "Not Found",
		})
		return
	}

	log.Debug().Str("provider", request.Provider).Msg("Got provider")

	// Create state
	state := provider.GenerateState()

	// Get auth URL
	authURL := provider.GetAuthURL(state)

	log.Debug().Msg("Got auth URL")

	// Set CSRF cookie
	c.SetCookie("tinyauth-csrf", state, int(time.Hour.Seconds()), "/", "", h.Config.CookieSecure, true)

	// Get redirect URI
	redirectURI := c.Query("redirect_uri")

	// Set redirect cookie if redirect URI is provided
	if redirectURI != "" {
		log.Debug().Str("redirectURI", redirectURI).Msg("Setting redirect cookie")
		c.SetCookie("tinyauth-redirect", redirectURI, int(time.Hour.Seconds()), "/", "", h.Config.CookieSecure, true)
	}

	// Return auth URL
	c.JSON(200, gin.H{
		"status":  200,
		"message": "OK",
		"url":     authURL,
	})
}

func (h *Handlers) OauthCallbackHandler(c *gin.Context) {
	// Create struct for OAuth request
	var providerName types.OAuthRequest

	// Bind URI
	err := c.BindUri(&providerName)

	// Handle error
	if err != nil {
		log.Error().Err(err).Msg("Failed to bind URI")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	log.Debug().Interface("provider", providerName.Provider).Msg("Got provider name")

	// Get state
	state := c.Query("state")

	// Get CSRF cookie
	csrfCookie, err := c.Cookie("tinyauth-csrf")

	if err != nil {
		log.Debug().Msg("No CSRF cookie")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	log.Debug().Str("csrfCookie", csrfCookie).Msg("Got CSRF cookie")

	// Check if CSRF cookie is valid
	if csrfCookie != state {
		log.Warn().Msg("Invalid CSRF cookie or CSRF cookie does not match with the state")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	// Clean up CSRF cookie
	c.SetCookie("tinyauth-csrf", "", -1, "/", "", h.Config.CookieSecure, true)

	// Get code
	code := c.Query("code")

	log.Debug().Msg("Got code")

	// Get provider
	provider := h.Providers.GetProvider(providerName.Provider)

	log.Debug().Str("provider", providerName.Provider).Msg("Got provider")

	// Provider does not exist
	if provider == nil {
		c.Redirect(http.StatusPermanentRedirect, "/not-found")
		return
	}

	// Exchange token (authenticates user)
	_, err = provider.ExchangeToken(code)

	log.Debug().Msg("Got token")

	// Handle error
	if err != nil {
		log.Error().Msg("Failed to exchange token")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	// Get email
	email, err := h.Providers.GetUser(providerName.Provider)

	log.Debug().Str("email", email).Msg("Got email")

	// Handle error
	if err != nil {
		log.Error().Msg("Failed to get email")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	// Email is not whitelisted
	if !h.Auth.EmailWhitelisted(email) {
		log.Warn().Str("email", email).Msg("Email not whitelisted")

		// Build query
		queries, err := query.Values(types.UnauthorizedQuery{
			Username: email,
		})

		// Handle error
		if err != nil {
			log.Error().Msg("Failed to build queries")
			c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
			return
		}

		// Redirect to unauthorized
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
	}

	log.Debug().Msg("Email whitelisted")

	// Create session cookie (also cleans up redirect cookie)
	h.Auth.CreateSessionCookie(c, &types.SessionCookie{
		Username: email,
		Provider: providerName.Provider,
	})

	// Check if we have a redirect URI
	redirectCookie, err := c.Cookie("tinyauth-redirect")

	if err != nil {
		log.Debug().Msg("No redirect cookie")
		c.Redirect(http.StatusPermanentRedirect, h.Config.AppURL)
		return
	}

	log.Debug().Str("redirectURI", redirectCookie).Msg("Got redirect URI")

	// Build query
	queries, err := query.Values(types.LoginQuery{
		RedirectURI: redirectCookie,
	})

	log.Debug().Msg("Got redirect query")

	// Handle error
	if err != nil {
		log.Error().Msg("Failed to build queries")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	// Clean up redirect cookie
	c.SetCookie("tinyauth-redirect", "", -1, "/", "", h.Config.CookieSecure, true)

	// Redirect to continue with the redirect URI
	c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/continue?%s", h.Config.AppURL, queries.Encode()))
}

func (h *Handlers) HealthcheckHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  200,
		"message": "OK",
	})
}
