package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"tinyauth/internal/auth"
	"tinyauth/internal/constants"
	"tinyauth/internal/docker"
	"tinyauth/internal/hooks"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
)

type Handlers struct {
	Config    types.HandlersConfig
	Auth      *auth.Auth
	Hooks     *hooks.Hooks
	Providers *providers.Providers
	Docker    *docker.Docker
}

func NewHandlers(config types.HandlersConfig, auth *auth.Auth, hooks *hooks.Hooks, providers *providers.Providers, docker *docker.Docker) *Handlers {
	return &Handlers{
		Config:    config,
		Auth:      auth,
		Hooks:     hooks,
		Providers: providers,
		Docker:    docker,
	}
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

	// Remove the port from the host if it exists
	hostPortless := strings.Split(host, ":")[0] // *lol*

	// Get the id
	id := strings.Split(hostPortless, ".")[0]

	// Get the container labels
	labels, err := h.Docker.GetLabels(id, hostPortless)

	log.Debug().Interface("labels", labels).Msg("Got labels")

	// Check if there was an error
	if err != nil {
		log.Error().Err(err).Msg("Failed to get container labels")

		if proxy.Proxy == "nginx" || !isBrowser {
			c.JSON(500, gin.H{
				"status":  500,
				"message": "Internal Server Error",
			})
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	// Get client IP
	ip := c.ClientIP()

	// Check if the IP is in bypass list
	if h.Auth.BypassedIP(labels, ip) {
		headersParsed := utils.ParseHeaders(labels.Headers)
		for key, value := range headersParsed {
			log.Debug().Str("key", key).Msg("Setting header")
			c.Header(key, value)
		}
		if labels.Basic.Username != "" && utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File) != "" {
			log.Debug().Str("username", labels.Basic.Username).Msg("Setting basic auth headers")
			c.Header("Authorization", fmt.Sprintf("Basic %s", utils.GetBasicAuth(labels.Basic.Username, utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File))))
		}
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	// Check if the IP is allowed/blocked
	if !h.Auth.CheckIP(labels, ip) {
		if proxy.Proxy == "nginx" || !isBrowser {
			c.JSON(403, gin.H{
				"status":  403,
				"message": "Forbidden",
			})
			return
		}

		values := types.UnauthorizedQuery{
			Resource: strings.Split(host, ".")[0],
			IP:       ip,
		}

		// Build query
		queries, err := query.Values(values)

		// Handle error
		if err != nil {
			log.Error().Err(err).Msg("Failed to build queries")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
		return
	}

	// Check if auth is enabled
	authEnabled, err := h.Auth.AuthEnabled(c, labels)

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

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	// If auth is not enabled, return 200
	if !authEnabled {
		headersParsed := utils.ParseHeaders(labels.Headers)
		for key, value := range headersParsed {
			log.Debug().Str("key", key).Msg("Setting header")
			c.Header(key, value)
		}
		if labels.Basic.Username != "" && utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File) != "" {
			log.Debug().Str("username", labels.Basic.Username).Msg("Setting basic auth headers")
			c.Header("Authorization", fmt.Sprintf("Basic %s", utils.GetBasicAuth(labels.Basic.Username, utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File))))
		}
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	// Get user context
	userContext := h.Hooks.UseUserContext(c)

	// If we are using basic auth, we need to check if the user has totp and if it does then disable basic auth
	if userContext.Provider == "basic" && userContext.TotpEnabled {
		log.Warn().Str("username", userContext.Username).Msg("User has totp enabled, disabling basic auth")
		userContext.IsLoggedIn = false
	}

	// Check if user is logged in
	if userContext.IsLoggedIn {
		log.Debug().Msg("Authenticated")

		// Check if user is allowed to access subdomain, if request is nginx.example.com the subdomain (resource) is nginx
		appAllowed := h.Auth.ResourceAllowed(c, userContext, labels)

		log.Debug().Bool("appAllowed", appAllowed).Msg("Checking if app is allowed")

		// The user is not allowed to access the app
		if !appAllowed {
			log.Warn().Str("username", userContext.Username).Str("host", host).Msg("User not allowed")

			if proxy.Proxy == "nginx" || !isBrowser {
				c.JSON(401, gin.H{
					"status":  401,
					"message": "Unauthorized",
				})
				return
			}

			// Values
			values := types.UnauthorizedQuery{
				Resource: strings.Split(host, ".")[0],
			}

			// Use either username or email
			if userContext.OAuth {
				values.Username = userContext.Email
			} else {
				values.Username = userContext.Username
			}

			// Build query
			queries, err := query.Values(values)

			// Handle error (no need to check for nginx/headers since we are sure we are using caddy/traefik)
			if err != nil {
				log.Error().Err(err).Msg("Failed to build queries")
				c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
				return
			}

			// We are using caddy/traefik so redirect
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
			return
		}

		// Check groups if using OAuth
		if userContext.OAuth {
			// Check if user is in required groups
			groupOk := h.Auth.OAuthGroup(c, userContext, labels)

			log.Debug().Bool("groupOk", groupOk).Msg("Checking if user is in required groups")

			// The user is not allowed to access the app
			if !groupOk {
				log.Warn().Str("username", userContext.Username).Str("host", host).Msg("User is not in required groups")

				if proxy.Proxy == "nginx" || !isBrowser {
					c.JSON(401, gin.H{
						"status":  401,
						"message": "Unauthorized",
					})
					return
				}

				// Values
				values := types.UnauthorizedQuery{
					Resource: strings.Split(host, ".")[0],
					GroupErr: true,
				}

				// Use either username or email
				if userContext.OAuth {
					values.Username = userContext.Email
				} else {
					values.Username = userContext.Username
				}

				// Build query
				queries, err := query.Values(values)

				// Handle error (no need to check for nginx/headers since we are sure we are using caddy/traefik)
				if err != nil {
					log.Error().Err(err).Msg("Failed to build queries")
					c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
					return
				}

				// We are using caddy/traefik so redirect
				c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
				return
			}
		}

		c.Header("Remote-User", utils.SanitizeHeader(userContext.Username))
		c.Header("Remote-Name", utils.SanitizeHeader(userContext.Name))
		c.Header("Remote-Email", utils.SanitizeHeader(userContext.Email))
		c.Header("Remote-Groups", utils.SanitizeHeader(userContext.OAuthGroups))

		// Set the rest of the headers
		parsedHeaders := utils.ParseHeaders(labels.Headers)
		for key, value := range parsedHeaders {
			log.Debug().Str("key", key).Msg("Setting header")
			c.Header(key, value)
		}

		// Set basic auth headers if configured
		if labels.Basic.Username != "" && utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File) != "" {
			log.Debug().Str("username", labels.Basic.Username).Msg("Setting basic auth headers")
			c.Header("Authorization", fmt.Sprintf("Basic %s", utils.GetBasicAuth(labels.Basic.Username, utils.GetSecret(labels.Basic.Password.Plain, labels.Basic.Password.File))))
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
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	log.Debug().Interface("redirect_uri", fmt.Sprintf("%s://%s%s", proto, host, uri)).Msg("Redirecting to login")

	// Redirect to login
	c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/login?%s", h.Config.AppURL, queries.Encode()))
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

	// Search for a user based on username
	userSearch := h.Auth.SearchUser(login.Username)

	log.Debug().Interface("userSearch", userSearch).Msg("Searching for user")

	// User does not exist
	if userSearch.Type == "" {
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
	if !h.Auth.VerifyUser(userSearch, login.Password) {
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

	// Check if user is using TOTP
	if userSearch.Type == "local" {
		// Get local user
		localUser := h.Auth.GetLocalUser(login.Username)

		// Check if TOTP is enabled
		if localUser.TotpSecret != "" {
			log.Debug().Msg("Totp enabled")

			// Set totp pending cookie
			h.Auth.CreateSessionCookie(c, &types.SessionCookie{
				Username:    login.Username,
				Name:        utils.Capitalize(login.Username),
				Email:       fmt.Sprintf("%s@%s", strings.ToLower(login.Username), h.Config.Domain),
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
	}

	// Create session cookie with username as provider
	h.Auth.CreateSessionCookie(c, &types.SessionCookie{
		Username: login.Username,
		Name:     utils.Capitalize(login.Username),
		Email:    fmt.Sprintf("%s@%s", strings.ToLower(login.Username), h.Config.Domain),
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
	user := h.Auth.GetLocalUser(userContext.Username)

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
		Name:     utils.Capitalize(user.Username),
		Email:    fmt.Sprintf("%s@%s", strings.ToLower(user.Username), h.Config.Domain),
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
		Status:                200,
		Message:               "OK",
		ConfiguredProviders:   configuredProviders,
		DisableContinue:       h.Config.DisableContinue,
		Title:                 h.Config.Title,
		GenericName:           h.Config.GenericName,
		Domain:                h.Config.Domain,
		ForgotPasswordMessage: h.Config.ForgotPasswordMessage,
		BackgroundImage:       h.Config.BackgroundImage,
		OAuthAutoRedirect:     h.Config.OAuthAutoRedirect,
		Version:               constants.Version,
		BuildTimestamp:        constants.BuildTimestamp,
		CommitHash:            constants.CommitHash,
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
		Name:        userContext.Name,
		Email:       userContext.Email,
		Provider:    userContext.Provider,
		Oauth:       userContext.OAuth,
		TotpPending: userContext.TotpPending,
	}

	// If we are not logged in we set the status to 401 else we set it to 200
	if !userContext.IsLoggedIn {
		log.Debug().Msg("Unauthorized")
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
	c.SetCookie(h.Config.CsrfCookieName, state, int(time.Hour.Seconds()), "/", "", h.Config.CookieSecure, true)

	// Get redirect URI
	redirectURI := c.Query("redirect_uri")

	// Set redirect cookie if redirect URI is provided
	if redirectURI != "" {
		log.Debug().Str("redirectURI", redirectURI).Msg("Setting redirect cookie")
		c.SetCookie(h.Config.RedirectCookieName, redirectURI, int(time.Hour.Seconds()), "/", "", h.Config.CookieSecure, true)
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
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	log.Debug().Interface("provider", providerName.Provider).Msg("Got provider name")

	// Get state
	state := c.Query("state")

	// Get CSRF cookie
	csrfCookie, err := c.Cookie(h.Config.CsrfCookieName)

	if err != nil {
		log.Debug().Msg("No CSRF cookie")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	log.Debug().Str("csrfCookie", csrfCookie).Msg("Got CSRF cookie")

	// Check if CSRF cookie is valid
	if csrfCookie != state {
		log.Warn().Msg("Invalid CSRF cookie or CSRF cookie does not match with the state")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	// Clean up CSRF cookie
	c.SetCookie(h.Config.CsrfCookieName, "", -1, "/", "", h.Config.CookieSecure, true)

	// Get code
	code := c.Query("code")

	log.Debug().Msg("Got code")

	// Get provider
	provider := h.Providers.GetProvider(providerName.Provider)

	log.Debug().Str("provider", providerName.Provider).Msg("Got provider")

	// Provider does not exist
	if provider == nil {
		c.Redirect(http.StatusTemporaryRedirect, "/not-found")
		return
	}

	// Exchange token (authenticates user)
	_, err = provider.ExchangeToken(code)

	log.Debug().Msg("Got token")

	// Handle error
	if err != nil {
		log.Error().Err(err).Msg("Failed to exchange token")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	// Get user
	user, err := h.Providers.GetUser(providerName.Provider)

	// Handle error
	if err != nil {
		log.Error().Msg("Failed to get user")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	log.Debug().Msg("Got user")

	// Check that email is not empty
	if user.Email == "" {
		log.Error().Msg("Email is empty")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	// Email is not whitelisted
	if !h.Auth.EmailWhitelisted(user.Email) {
		log.Warn().Str("email", user.Email).Msg("Email not whitelisted")

		// Build query
		queries, err := query.Values(types.UnauthorizedQuery{
			Username: user.Email,
		})

		// Handle error
		if err != nil {
			log.Error().Err(err).Msg("Failed to build queries")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
			return
		}

		// Redirect to unauthorized
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
	}

	log.Debug().Msg("Email whitelisted")

	// Get username
	var username string

	if user.PreferredUsername != "" {
		username = user.PreferredUsername
	} else {
		username = fmt.Sprintf("%s_%s", strings.Split(user.Email, "@")[0], strings.Split(user.Email, "@")[1])
	}

	// Get name
	var name string

	if user.Name != "" {
		name = user.Name
	} else {
		name = fmt.Sprintf("%s (%s)", utils.Capitalize(strings.Split(user.Email, "@")[0]), strings.Split(user.Email, "@")[1])
	}

	// Create session cookie (also cleans up redirect cookie)
	h.Auth.CreateSessionCookie(c, &types.SessionCookie{
		Username:    username,
		Name:        name,
		Email:       user.Email,
		Provider:    providerName.Provider,
		OAuthGroups: strings.Join(user.Groups, ","),
	})

	// Check if we have a redirect URI
	redirectCookie, err := c.Cookie(h.Config.RedirectCookieName)

	if err != nil {
		log.Debug().Msg("No redirect cookie")
		c.Redirect(http.StatusTemporaryRedirect, h.Config.AppURL)
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
		log.Error().Err(err).Msg("Failed to build queries")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", h.Config.AppURL))
		return
	}

	// Clean up redirect cookie
	c.SetCookie(h.Config.RedirectCookieName, "", -1, "/", "", h.Config.CookieSecure, true)

	// Redirect to continue with the redirect URI
	c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/continue?%s", h.Config.AppURL, queries.Encode()))
}

func (h *Handlers) HealthcheckHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  200,
		"message": "OK",
	})
}
