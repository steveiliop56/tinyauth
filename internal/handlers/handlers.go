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
    var proxy types.Proxy // Declaration for proxy
    err := c.BindUri(&proxy)
    if err != nil {
        log.Error().Err(err).Msg("Failed to bind URI")
        c.JSON(400, gin.H{"status": 400,"message": "Bad Request"})
        return
    }

    isBrowser := strings.Contains(c.Request.Header.Get("Accept"), "text/html") 



	log.Debug().Interface("proxy", proxy.Proxy).Msg("Got proxy")

	uri := c.Request.Header.Get("X-Forwarded-Uri")
	proto := c.Request.Header.Get("X-Forwarded-Proto")
	host := c.Request.Header.Get("X-Forwarded-Host")

	authEnabled, err := h.Auth.AuthEnabled(c)

	appId := strings.Split(host, ".")[0]
	labels, err := h.Docker.GetLabels(appId)

	if !authEnabled {
		// Set label headers only if auth is disabled
		for key, value := range labels.Headers {
			log.Debug().Str("key", key).Str("value", value).Msg("Setting label header (auth disabled)")
			c.Header(key, value)
		}
		c.JSON(200, gin.H{"status": 200, "message": "Authenticated (Auth Disabled)"})
		return
	}

	userContext := h.Hooks.UseUserContext(c)

	if userContext.IsLoggedIn {
		log.Debug().Msg("User is logged in, checking resource access")

		appAllowed, err := h.Auth.ResourceAllowed(c, userContext)
		if err != nil {
			// ... (error handling for ResourceAllowed) ...
			return
		}

		log.Debug().Bool("appAllowed", appAllowed).Msg("Checking if app is allowed")

		if !appAllowed {
			log.Warn().Str("username", userContext.Username).Str("host", host).Msg("User not allowed for this resource")
			c.Header("WWW-Authenticate", "Basic realm=\"tinyauth\"")
			if proxy.Proxy == "nginx" || !isBrowser {
				c.JSON(401, gin.H{"status": 401, "message": "Unauthorized"})
			} else {
				// ... (redirect to /unauthorized) ...
			}
			return
		}

		// --- ADD CLAIMS HEADER LOGIC ---
		if userContext.Claims != nil {
			log.Debug().Msg("Setting headers from claims")
			for key, value := range userContext.Claims {
				// Sanitize header key slightly (replace common disallowed chars, case is handled by Go's http library)
				headerKeySanitized := strings.ReplaceAll(key, ".", "-")
				headerKeySanitized = strings.ReplaceAll(headerKeySanitized, "_", "-")
				headerName := fmt.Sprintf("X-Claim-%s", headerKeySanitized)
				headerValue := ""

				switch v := value.(type) {
				case string:
					headerValue = v
				case bool:
					headerValue = fmt.Sprintf("%t", v)
				case float64: // Numbers often parse as float64 from JSON
					// Format as integer if it has no fractional part
					if v == float64(int64(v)) {
						headerValue = fmt.Sprintf("%d", int64(v))
					} else {
						headerValue = fmt.Sprintf("%f", v)
					}
				// Add cases for int, etc. if needed and they aren't covered by float64
				case []interface{}:
					strValues := make([]string, len(v))
					for i, item := range v {
						strValues[i] = fmt.Sprintf("%v", item)
					}
					headerValue = strings.Join(strValues, ",")
				default:
					// Attempt to convert other types, might result in "[value]" or similar
					headerValue = fmt.Sprintf("%v", v)
					log.Warn().Str("key", key).Str("type", fmt.Sprintf("%T", v)).Msg("Unhandled claim type, using default string conversion for header")
				}

				if headerValue != "" {
					log.Debug().Str("key", headerName).Str("value", headerValue).Msg("Setting claim header")
					// Use Set to overwrite if duplicate claim keys map to same sanitized header
					c.Header(headerName, headerValue)
				}
			}
		}
		// --- END CLAIMS HEADER LOGIC ---

		// Set standard headers (Remote-User and from docker labels)
		c.Header("Remote-User", userContext.Username)
		for key, value := range labels.Headers {
			log.Debug().Str("key", key).Str("value", value).Msg("Setting label header")
			c.Header(key, value)
		}

		log.Debug().Msg("Authenticated and authorized, returning 200 OK")
		c.JSON(200, gin.H{
			"status":  200,
			"message": "Authenticated",
		})
		return
	}

	// User is not logged in
	log.Debug().Msg("Unauthorized, redirecting to login or returning 401")
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
		Status:                200,
		Message:               "OK",
		ConfiguredProviders:   configuredProviders,
		DisableContinue:       h.Config.DisableContinue,
		Title:                 h.Config.Title,
		GenericName:           h.Config.GenericName,
		Domain:                h.Config.Domain,
		ForgotPasswordMessage: h.Config.ForgotPasswordMessage,
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
	var providerName types.OAuthRequest
	err := c.BindUri(&providerName)
	if err != nil {
		// ... (error handling) ...
		return
	}
	log.Debug().Interface("provider", providerName.Provider).Msg("Got provider name for callback")

	state := c.Query("state")
	csrfCookie, err := c.Cookie("tinyauth-csrf")
	if err != nil || csrfCookie != state {
		log.Warn().Msg("Invalid or missing CSRF cookie/state mismatch")
		c.SetCookie("tinyauth-csrf", "", -1, "/", "", h.Config.CookieSecure, true) // Clean up bad cookie
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=csrf", h.Config.AppURL))
		return
	}
	c.SetCookie("tinyauth-csrf", "", -1, "/", "", h.Config.CookieSecure, true) // Clean up valid CSRF cookie

	code := c.Query("code")
	log.Debug().Msg("Got authorization code")

	provider := h.Providers.GetProvider(providerName.Provider)
	if provider == nil {
		log.Error().Str("provider", providerName.Provider).Msg("Provider not found during callback")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=provider_not_found", h.Config.AppURL))
		return
	}

	// --- MODIFY ExchangeToken CALL ---
	// Call the modified ExchangeToken which returns the full token
	token, err := provider.ExchangeToken(code)
	if err != nil {
		log.Error().Err(err).Msg("Failed to exchange token")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=token_exchange", h.Config.AppURL))
		return
	}
	log.Debug().Msg("Exchanged token successfully")

	// --- MODIFY GetUser CALL ---
	// Call the modified GetUser, passing the full token
	identifier, claims, err := h.Providers.GetUser(providerName.Provider, token)
	if err != nil {
		log.Error().Err(err).Str("provider", providerName.Provider).Msg("Failed to get user info")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=user_info", h.Config.AppURL))
		return
	}
	log.Debug().Str("identifier", identifier).Interface("claims", claims).Msg("Got user info")

	// Check whitelist using the identifier (email or sub)
	if !h.Auth.EmailWhitelisted(identifier) {
		log.Warn().Str("identifier", identifier).Msg("Identifier not whitelisted")
		queries, _ := query.Values(types.UnauthorizedQuery{Username: identifier}) // Use identifier here
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/unauthorized?%s", h.Config.AppURL, queries.Encode()))
		return // Stop processing
	}
	log.Debug().Msg("Identifier whitelisted")

	// --- MODIFY CreateSessionCookie CALL ---
	// Create session cookie, passing the identifier and the claims map
	err = h.Auth.CreateSessionCookie(c, &types.SessionCookie{
		Username: identifier, // Use the identifier (email/sub)
		Provider: providerName.Provider,
		Claims:   claims, // Pass the claims map here
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to create session cookie after OAuth callback")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=session_creation", h.Config.AppURL))
		return
	}

	// --- Redirect logic remains the same ---
	redirectCookie, err := c.Cookie("tinyauth-redirect")
	if err != nil {
		log.Debug().Msg("No redirect cookie, redirecting to AppURL")
		c.Redirect(http.StatusPermanentRedirect, h.Config.AppURL)
		return
	}
	log.Debug().Str("redirectURI", redirectCookie).Msg("Got redirect URI from cookie")

	queries, err := query.Values(types.LoginQuery{RedirectURI: redirectCookie})
	if err != nil {
		log.Error().Err(err).Msg("Failed to build redirect query")
		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/error?reason=redirect_query", h.Config.AppURL))
		return
	}

	c.SetCookie("tinyauth-redirect", "", -1, "/", "", h.Config.CookieSecure, true) // Clean up redirect cookie
	c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/continue?%s", h.Config.AppURL, queries.Encode()))
}

func (h *Handlers) HealthcheckHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  200,
		"message": "OK",
	})
}
