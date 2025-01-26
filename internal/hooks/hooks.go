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
	cookie, cookiErr := hooks.Auth.GetSessionCookie(c)

	if cookiErr != nil {
		log.Error().Err(cookiErr).Msg("Failed to get session cookie")
		return types.UserContext{
			Username:   "",
			IsLoggedIn: false,
			OAuth:      false,
			Provider:   "",
		}
	}

	if cookie.Provider == "username" {
		if hooks.Auth.GetUser(cookie.Username) != nil {
			return types.UserContext{
				Username:   cookie.Username,
				IsLoggedIn: true,
				OAuth:      false,
				Provider:   "",
			}
		}
	}

	provider := hooks.Providers.GetProvider(cookie.Provider)

	if provider != nil {
		if !hooks.Auth.EmailWhitelisted(cookie.Username) {
			log.Error().Msgf("Email %s not whitelisted", cookie.Username)
			hooks.Auth.DeleteSessionCookie(c)
			return types.UserContext{
				Username:   "",
				IsLoggedIn: false,
				OAuth:      false,
				Provider:   "",
			}
		}
		return types.UserContext{
			Username:   cookie.Username,
			IsLoggedIn: true,
			OAuth:      true,
			Provider:   cookie.Provider,
		}
	}

	return types.UserContext{
		Username:   "",
		IsLoggedIn: false,
		OAuth:      false,
		Provider:   "",
	}
}
