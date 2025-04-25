package hooks

import (
	"tinyauth/internal/auth"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func NewHooks(auth *auth.Auth, providers *providers.Providers) *Hooks {
	return &Hooks{
		Auth:      auth,
		Providers: providers,
	}
}

type Hooks struct {
	Auth      *auth.Auth
	Providers *providers.Providers
}

func (hooks *Hooks) UseUserContext(c *gin.Context) types.UserContext {
	// Get session cookie (which now includes claims) and basic auth
	cookie, err := hooks.Auth.GetSessionCookie(c) // This now returns claims if available
	basic := hooks.Auth.GetBasicAuth(c)

	// Check if basic auth is set
	if basic != nil {
		log.Debug().Msg("Got basic auth")
		user := hooks.Auth.GetUser(basic.Username)
		if user != nil && hooks.Auth.CheckPassword(*user, basic.Password) {
			// Basic auth doesn't have OIDC claims
			return types.UserContext{
				Username:    basic.Username,
				IsLoggedIn:  true,
				OAuth:       false,
				Provider:    "basic",
				TotpPending: false,
				Claims:      nil, // Explicitly nil for basic auth
			}
		}
	}

	// Check cookie error after basic auth
	if err != nil {
		log.Error().Err(err).Msg("Failed to get session cookie")
		// Return empty context, including nil claims
		return types.UserContext{
			Username:    "",
			IsLoggedIn:  false,
			OAuth:       false,
			Provider:    "",
			TotpPending: false,
			Claims:      nil,
		}
	}

	// Check if session cookie has totp pending
	if cookie.TotpPending {
		log.Debug().Msg("Totp pending")
		// Return context indicating TOTP is pending, include claims if present (though typically not used here)
		return types.UserContext{
			Username:    cookie.Username,
			IsLoggedIn:  false, // Not fully logged in yet
			OAuth:       cookie.Provider != "username" && cookie.Provider != "basic", // Infer OAuth based on provider
			Provider:    cookie.Provider,
			TotpPending: true,
			Claims:      cookie.Claims, // Carry over claims
		}
	}

	// Check if session cookie represents a valid login (username/password or OAuth)
	isLoggedIn := false
	isOAuth := false

	if cookie.Username != "" { // Check if there's actually a user in the cookie
		if cookie.Provider == "username" {
			if hooks.Auth.GetUser(cookie.Username) != nil {
				log.Debug().Msg("Valid username/password session found")
				isLoggedIn = true
				isOAuth = false
			} else {
				log.Warn().Str("username", cookie.Username).Msg("User from session cookie not found, deleting session.")
				hooks.Auth.DeleteSessionCookie(c) // Clean up invalid session
			}
		} else { // Assume OAuth provider
			provider := hooks.Providers.GetProvider(cookie.Provider)
			if provider != nil {
				// Check whitelist (re-check might be redundant if strictly enforced on callback, but safe)
				if hooks.Auth.EmailWhitelisted(cookie.Username) {
					log.Debug().Str("provider", cookie.Provider).Msg("Valid OAuth session found")
					isLoggedIn = true
					isOAuth = true
				} else {
					log.Warn().Str("username", cookie.Username).Str("provider", cookie.Provider).Msg("User from OAuth session cookie not whitelisted, deleting session.")
					hooks.Auth.DeleteSessionCookie(c) // Clean up invalid session
				}
			} else {
				log.Warn().Str("provider", cookie.Provider).Msg("Provider from session cookie not found/configured, deleting session.")
				hooks.Auth.DeleteSessionCookie(c) // Clean up invalid session
			}
		}
	}

	// Return the final context
	return types.UserContext{
		Username:    cookie.Username, // Use username from cookie if logged in
		IsLoggedIn:  isLoggedIn,
		OAuth:       isOAuth,
		Provider:    cookie.Provider, // Use provider from cookie if logged in
		TotpPending: false,         // Already handled above
		Claims:      cookie.Claims, // Pass claims through
	}
}
