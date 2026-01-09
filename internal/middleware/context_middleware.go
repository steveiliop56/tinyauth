package middleware

import (
	"fmt"
	"strings"
	"time"

	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/service"
	"github.com/steveiliop56/tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type ContextMiddlewareConfig struct {
	CookieDomain string
}

type ContextMiddleware struct {
	config ContextMiddlewareConfig
	auth   *service.AuthService
	broker *service.OAuthBrokerService
}

func NewContextMiddleware(config ContextMiddlewareConfig, auth *service.AuthService, broker *service.OAuthBrokerService) *ContextMiddleware {
	return &ContextMiddleware{
		config: config,
		auth:   auth,
		broker: broker,
	}
}

func (m *ContextMiddleware) Init() error {
	return nil
}

func (m *ContextMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := m.auth.GetSessionCookie(c)

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
			userSearch := m.auth.SearchUser(cookie.Username)

			if userSearch.Type == "unknown" || userSearch.Type == "error" {
				log.Debug().Msg("User from session cookie not found")
				m.auth.DeleteSessionCookie(c)
				goto basic
			}

			m.auth.RefreshSessionCookie(c)
			c.Set("context", &config.UserContext{
				Username:   cookie.Username,
				Name:       cookie.Name,
				Email:      cookie.Email,
				Provider:   "username",
				IsLoggedIn: true,
				LdapGroups: cookie.LdapGroups,
			})
			c.Next()
			return
		default:
			_, exists := m.broker.GetService(cookie.Provider)

			if !exists {
				log.Debug().Msg("OAuth provider from session cookie not found")
				m.auth.DeleteSessionCookie(c)
				goto basic
			}

			if !m.auth.IsEmailWhitelisted(cookie.Email) {
				log.Debug().Msg("Email from session cookie not whitelisted")
				m.auth.DeleteSessionCookie(c)
				goto basic
			}

			m.auth.RefreshSessionCookie(c)
			c.Set("context", &config.UserContext{
				Username:    cookie.Username,
				Name:        cookie.Name,
				Email:       cookie.Email,
				Provider:    cookie.Provider,
				OAuthGroups: cookie.OAuthGroups,
				OAuthName:   cookie.OAuthName,
				OAuthSub:    cookie.OAuthSub,
				IsLoggedIn:  true,
				OAuth:       true,
			})
			c.Next()
			return
		}

	basic:
		basic := m.auth.GetBasicAuth(c)

		if basic == nil {
			log.Debug().Msg("No basic auth provided")
			c.Next()
			return
		}

		locked, remaining := m.auth.IsAccountLocked(basic.Username)

		if locked {
			log.Debug().Msgf("Account for user %s is locked for %d seconds, denying auth", basic.Username, remaining)
			c.Writer.Header().Add("x-tinyauth-lock-locked", "true")
			c.Writer.Header().Add("x-tinyauth-lock-reset", time.Now().Add(time.Duration(remaining)*time.Second).Format(time.RFC3339))
			c.Next()
			return
		}

		userSearch := m.auth.SearchUser(basic.Username)

		if userSearch.Type == "unknown" || userSearch.Type == "error" {
			m.auth.RecordLoginAttempt(basic.Username, false)
			log.Debug().Msg("User from basic auth not found")
			c.Next()
			return
		}

		if !m.auth.VerifyUser(userSearch, basic.Password) {
			m.auth.RecordLoginAttempt(basic.Username, false)
			log.Debug().Msg("Invalid password for basic auth user")
			c.Next()
			return
		}

		m.auth.RecordLoginAttempt(basic.Username, true)

		switch userSearch.Type {
		case "local":
			log.Debug().Msg("Basic auth user is local")

			user := m.auth.GetLocalUser(basic.Username)

			c.Set("context", &config.UserContext{
				Username:    user.Username,
				Name:        utils.Capitalize(user.Username),
				Email:       fmt.Sprintf("%s@%s", strings.ToLower(user.Username), m.config.CookieDomain),
				Provider:    "username",
				IsLoggedIn:  true,
				TotpEnabled: user.TotpSecret != "",
			})
			c.Next()
			return
		case "ldap":
			log.Debug().Msg("Basic auth user is LDAP")

			ldapUser, err := m.auth.GetLdapUser(basic.Username)

			if err != nil {
				log.Debug().Err(err).Msg("Error retrieving LDAP user details")
				c.Next()
				return
			}

			c.Set("context", &config.UserContext{
				Username:   basic.Username,
				Name:       utils.Capitalize(basic.Username),
				Email:      fmt.Sprintf("%s@%s", strings.ToLower(basic.Username), m.config.CookieDomain),
				Provider:   "ldap",
				IsLoggedIn: true,
				LdapGroups: strings.Join(ldapUser.Groups, ","),
			})
			c.Next()
			return
		}

		c.Next()
	}
}
