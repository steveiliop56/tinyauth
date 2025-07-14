package hooks

import (
	"fmt"
	"strings"
	"tinyauth/internal/auth"
	"tinyauth/internal/oauth"
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
	cookie, err := hooks.Auth.GetSessionCookie(c)
	var provider *oauth.OAuth

	if err != nil {
		log.Error().Err(err).Msg("Failed to get session cookie")
		goto basic
	}

	if cookie.TotpPending {
		log.Debug().Msg("Totp pending")
		return types.UserContext{
			Username:    cookie.Username,
			Name:        cookie.Name,
			Email:       cookie.Email,
			Provider:    cookie.Provider,
			TotpPending: true,
		}
	}

	if cookie.Provider == "username" {
		log.Debug().Msg("Provider is username")

		userSearch := hooks.Auth.SearchUser(cookie.Username)

		if userSearch.Type == "unknown" {
			log.Warn().Str("username", cookie.Username).Msg("User does not exist")
			goto basic
		}

		log.Debug().Str("type", userSearch.Type).Msg("User exists")

		return types.UserContext{
			Username:   cookie.Username,
			Name:       cookie.Name,
			Email:      cookie.Email,
			IsLoggedIn: true,
			Provider:   "username",
		}
	}

	log.Debug().Msg("Provider is not username")

	provider = hooks.Providers.GetProvider(cookie.Provider)

	if provider != nil {
		log.Debug().Msg("Provider exists")

		if !hooks.Auth.EmailWhitelisted(cookie.Email) {
			log.Warn().Str("email", cookie.Email).Msg("Email is not whitelisted")
			hooks.Auth.DeleteSessionCookie(c)
			goto basic
		}

		log.Debug().Msg("Email is whitelisted")

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

basic:
	log.Debug().Msg("Trying basic auth")

	basic := hooks.Auth.GetBasicAuth(c)

	if basic != nil {
		log.Debug().Msg("Got basic auth")

		userSearch := hooks.Auth.SearchUser(basic.Username)

		if userSearch.Type == "unkown" {
			log.Error().Str("username", basic.Username).Msg("Basic auth user does not exist")
			return types.UserContext{}
		}

		if !hooks.Auth.VerifyUser(userSearch, basic.Password) {
			log.Error().Str("username", basic.Username).Msg("Basic auth user password incorrect")
			return types.UserContext{}
		}

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

	return types.UserContext{}
}
