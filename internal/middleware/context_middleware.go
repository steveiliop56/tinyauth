package middlewares

import (
	"fmt"
	"strings"
	"tinyauth/internal/auth"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
)

type ContextMiddlewareConfig struct {
	Domain string
}

type ContextMiddleware struct {
	Config    ContextMiddlewareConfig
	Auth      *auth.Auth
	Providers *providers.Providers
}

func NewContextMiddleware(config ContextMiddlewareConfig, auth *auth.Auth, providers *providers.Providers) *ContextMiddleware {
	return &ContextMiddleware{
		Config:    config,
		Auth:      auth,
		Providers: providers,
	}
}

func (m *ContextMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := m.Auth.GetSessionCookie(c)

		if err != nil {
			goto basic
		}

		if cookie.TotpPending {
			c.Set("context", &types.UserContext{
				Username:    cookie.Username,
				Name:        cookie.Name,
				Email:       cookie.Email,
				Provider:    "username",
				TotpPending: true,
				TotpEnabled: true,
			})
			c.Next()
			return
		}

		switch cookie.Provider {
		case "username":
			userSearch := m.Auth.SearchUser(cookie.Username)

			if userSearch.Type == "unknown" {
				goto basic
			}

			c.Set("context", &types.UserContext{
				Username:   cookie.Username,
				Name:       cookie.Name,
				Email:      cookie.Email,
				Provider:   "username",
				IsLoggedIn: true,
			})
			c.Next()
			return
		default:
			provider := m.Providers.GetProvider(cookie.Provider)

			if provider == nil {
				goto basic
			}

			if !m.Auth.EmailWhitelisted(cookie.Email) {
				m.Auth.DeleteSessionCookie(c)
				goto basic
			}

			c.Set("context", &types.UserContext{
				Username:    cookie.Username,
				Name:        cookie.Name,
				Email:       cookie.Email,
				Provider:    cookie.Provider,
				OAuthGroups: cookie.OAuthGroups,
				IsLoggedIn:  true,
				OAuth:       true,
			})
			c.Next()
			return
		}

	basic:
		basic := m.Auth.GetBasicAuth(c)

		if basic == nil {
			c.Next()
			return
		}

		userSearch := m.Auth.SearchUser(basic.Username)

		if userSearch.Type == "unknown" {
			c.Next()
			return
		}

		if !m.Auth.VerifyUser(userSearch, basic.Password) {
			c.Next()
			return
		}

		switch userSearch.Type {
		case "local":
			user := m.Auth.GetLocalUser(basic.Username)

			c.Set("context", &types.UserContext{
				Username:    user.Username,
				Name:        utils.Capitalize(user.Username),
				Email:       fmt.Sprintf("%s@%s", strings.ToLower(user.Username), m.Config.Domain),
				Provider:    "basic",
				IsLoggedIn:  true,
				TotpEnabled: user.TotpSecret != "",
			})
			c.Next()
			return
		case "ldap":
			c.Set("context", &types.UserContext{
				Username:   basic.Username,
				Name:       utils.Capitalize(basic.Username),
				Email:      fmt.Sprintf("%s@%s", strings.ToLower(basic.Username), m.Config.Domain),
				Provider:   "basic",
				IsLoggedIn: true,
			})
			c.Next()
			return
		}

		c.Next()
	}
}
