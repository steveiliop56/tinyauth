package middleware

import (
	"fmt"
	"strings"
	"tinyauth/internal/config"
	"tinyauth/internal/service"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type ContextMiddlewareConfig struct {
	Domain string
}

type ContextMiddleware struct {
	Config ContextMiddlewareConfig
	Auth   *service.AuthService
	Broker *service.OAuthBrokerService
}

func NewContextMiddleware(config ContextMiddlewareConfig, auth *service.AuthService, broker *service.OAuthBrokerService) *ContextMiddleware {
	return &ContextMiddleware{
		Config: config,
		Auth:   auth,
		Broker: broker,
	}
}

func (m *ContextMiddleware) Init() error {
	return nil
}

func (m *ContextMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := m.Auth.GetSessionCookie(c)

		if err != nil {
			log.Debug().Err(err).Msg("No valid session cookie found")
			goto basic
		}

		if cookie.TotpPending {
			c.Set("context", &config.UserContext{
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
				log.Debug().Msg("User from session cookie not found")
				m.Auth.DeleteSessionCookie(c)
				goto basic
			}

			c.Set("context", &config.UserContext{
				Username:   cookie.Username,
				Name:       cookie.Name,
				Email:      cookie.Email,
				Provider:   "username",
				IsLoggedIn: true,
			})
			c.Next()
			return
		default:
			_, exists := m.Broker.GetService(cookie.Provider)

			if !exists {
				log.Debug().Msg("OAuth provider from session cookie not found")
				m.Auth.DeleteSessionCookie(c)
				goto basic
			}

			if !m.Auth.IsEmailWhitelisted(cookie.Email) {
				log.Debug().Msg("Email from session cookie not whitelisted")
				m.Auth.DeleteSessionCookie(c)
				goto basic
			}

			c.Set("context", &config.UserContext{
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
			log.Debug().Msg("No basic auth provided")
			c.Next()
			return
		}

		userSearch := m.Auth.SearchUser(basic.Username)

		if userSearch.Type == "unknown" {
			log.Debug().Msg("User from basic auth not found")
			c.Next()
			return
		}

		if !m.Auth.VerifyUser(userSearch, basic.Password) {
			log.Debug().Msg("Invalid password for basic auth user")
			c.Next()
			return
		}

		switch userSearch.Type {
		case "local":
			log.Debug().Msg("Basic auth user is local")

			user := m.Auth.GetLocalUser(basic.Username)

			c.Set("context", &config.UserContext{
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
			log.Debug().Msg("Basic auth user is LDAP")
			c.Set("context", &config.UserContext{
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
