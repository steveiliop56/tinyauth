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
	// Get session cookie and basic auth
	cookie := hooks.Auth.GetSessionCookie(c)
	basic := hooks.Auth.GetBasicAuth(c)

	// Check if basic auth is set
	if basic.Username != "" {
		log.Debug().Msg("Got basic auth")

		// Check if user exists and password is correct
		user := hooks.Auth.GetUser(basic.Username)

		if user != nil && hooks.Auth.CheckPassword(*user, basic.Password) {
			// Return user context since we are logged in with basic auth
			return types.UserContext{
				Username:   basic.Username,
				IsLoggedIn: true,
				OAuth:      false,
				Provider:   "basic",
			}
		}

	}

	// Check if session cookie is username/password auth
	if cookie.Provider == "username" {
		log.Debug().Msg("Provider is username")

		// Check if user exists
		if hooks.Auth.GetUser(cookie.Username) != nil {
			log.Debug().Msg("User exists")

			// It exists so we are logged in
			return types.UserContext{
				Username:   cookie.Username,
				IsLoggedIn: true,
				OAuth:      false,
				Provider:   "username",
			}
		}
	}

	log.Debug().Msg("Provider is not username")

	// The provider is not username so we need to check if it is an oauth provider
	provider := hooks.Providers.GetProvider(cookie.Provider)

	// If we have a provider with this name
	if provider != nil {
		log.Debug().Msg("Provider exists")

		// Check if the oauth email is whitelisted
		if !hooks.Auth.EmailWhitelisted(cookie.Username) {
			log.Error().Str("email", cookie.Username).Msg("Email is not whitelisted")

			// It isn't so we delete the cookie and return an empty context
			hooks.Auth.DeleteSessionCookie(c)

			// Return empty context
			return types.UserContext{
				Username:   "",
				IsLoggedIn: false,
				OAuth:      false,
				Provider:   "",
			}
		}

		log.Debug().Msg("Email is whitelisted")

		// Return user context since we are logged in with oauth
		return types.UserContext{
			Username:   cookie.Username,
			IsLoggedIn: true,
			OAuth:      true,
			Provider:   cookie.Provider,
		}
	}

	// Neither basic auth or oauth is set so we return an empty context
	return types.UserContext{
		Username:   "",
		IsLoggedIn: false,
		OAuth:      false,
		Provider:   "",
	}
}
