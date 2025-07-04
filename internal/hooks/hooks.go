package hooks

import (
	"fmt"
	"strings"
	"tinyauth/internal/auth"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type Hooks struct {
	Config    types.HooksConfig
	Auth      *auth.Auth
	Providers *providers.Providers
}

func NewHooks(config types.HooksConfig, auth *auth.Auth, providers *providers.Providers) *Hooks {
	return &Hooks{
		Config:    config,
		Auth:      auth,
		Providers: providers,
	}
}

func (hooks *Hooks) UseUserContext(c *gin.Context) types.UserContext {
	// Get session cookie and basic auth
	cookie, err := hooks.Auth.GetSessionCookie(c)
	basic := hooks.Auth.GetBasicAuth(c)

	// Check if basic auth is set
	if basic != nil {
		log.Debug().Msg("Got basic auth")

		// Get user
		userSearch := hooks.Auth.GetUser(basic.Username)

		if userSearch.Type == "" {
			log.Error().Str("username", basic.Username).Msg("User does not exist")

			// Return empty context
			return types.UserContext{}
		}

		// Verify the user
		if !hooks.Auth.VerifyUser(userSearch, basic.Password) {
			log.Error().Str("username", basic.Username).Msg("Password incorrect")

			// Return empty context
			return types.UserContext{}
		}

		// Get the user type
		if userSearch.Type == "ldap" {
			log.Debug().Msg("User is LDAP")

			return types.UserContext{
				Username:    basic.Username,
				Name:        utils.Capitalize(basic.Username),
				Email:       fmt.Sprintf("%s@%s", strings.ToLower(basic.Username), hooks.Config.Domain),
				IsLoggedIn:  true,
				Provider:    "basic",
				TotpEnabled: false,
			}
		}

		user := hooks.Auth.GetLocalUser(basic.Username)

		return types.UserContext{
			Username:    basic.Username,
			Name:        utils.Capitalize(basic.Username),
			Email:       fmt.Sprintf("%s@%s", strings.ToLower(basic.Username), hooks.Config.Domain),
			IsLoggedIn:  true,
			Provider:    "basic",
			TotpEnabled: user.TotpSecret != "",
		}

	}

	// Check cookie error after basic auth
	if err != nil {
		log.Error().Err(err).Msg("Failed to get session cookie")
		// Return empty context
		return types.UserContext{}
	}

	// Check if session cookie has totp pending
	if cookie.TotpPending {
		log.Debug().Msg("Totp pending")
		// Return empty context since we are pending totp
		return types.UserContext{
			Username:    cookie.Username,
			Name:        cookie.Name,
			Email:       cookie.Email,
			Provider:    cookie.Provider,
			TotpPending: true,
		}
	}

	// Check if session cookie is username/password auth
	if cookie.Provider == "username" {
		log.Debug().Msg("Provider is username")

		// Get user
		userSearch := hooks.Auth.GetUser(cookie.Username)

		if userSearch.Type == "" {
			log.Error().Str("username", cookie.Username).Msg("User does not exist")

			// Return empty context
			return types.UserContext{}
		}

		log.Debug().Str("type", userSearch.Type).Msg("User exists")

		// It exists so we are logged in
		return types.UserContext{
			Username:   cookie.Username,
			Name:       cookie.Name,
			Email:      cookie.Email,
			IsLoggedIn: true,
			Provider:   "username",
		}
	}

	log.Debug().Msg("Provider is not username")

	// The provider is not username so we need to check if it is an oauth provider
	provider := hooks.Providers.GetProvider(cookie.Provider)

	// If we have a provider with this name
	if provider != nil {
		log.Debug().Msg("Provider exists")

		// Check if the oauth email is whitelisted
		if !hooks.Auth.EmailWhitelisted(cookie.Email) {
			log.Error().Str("email", cookie.Email).Msg("Email is not whitelisted")

			// It isn't so we delete the cookie and return an empty context
			hooks.Auth.DeleteSessionCookie(c)

			// Return empty context
			return types.UserContext{}
		}

		log.Debug().Msg("Email is whitelisted")

		// Return user context since we are logged in with oauth
		return types.UserContext{
			Username:    cookie.Username,
			Name:        cookie.Name,
			Email:       cookie.Email,
			IsLoggedIn:  true,
			OAuth:       true,
			Provider:    cookie.Provider,
			OAuthGroups: cookie.OAuthGroups,
		}
	}

	// Neither basic auth or oauth is set so we return an empty context
	return types.UserContext{}
}
