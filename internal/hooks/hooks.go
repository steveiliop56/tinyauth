package hooks

import (
	"strings"
	"tinyauth/internal/auth"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
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

func (hooks *Hooks) UseUserContext(c *gin.Context) (types.UserContext, error) {
	session := sessions.Default(c)
	sessionCookie := session.Get("tinyauth_sid")

	if sessionCookie == nil {
		return types.UserContext{
			Email:      "",
			IsLoggedIn: false,
			OAuth:      false,
			Provider:   "",
		}, nil
	}

	data, dataOk := sessionCookie.(string)

	if !dataOk {
		return types.UserContext{
			Email:      "",
			IsLoggedIn: false,
			OAuth:      false,
			Provider:   "",
		}, nil
	}

	split := strings.Split(data, ":")

	if len(split) != 2 {
		return types.UserContext{
			Email:      "",
			IsLoggedIn: false,
			OAuth:      false,
			Provider:   "",
		}, nil
	}

	sessionType := split[0]
	sessionValue := split[1]

	if sessionType == "email" {
		user := hooks.Auth.GetUser(sessionValue)
		if user == nil {
			return types.UserContext{
				Email:      "",
				IsLoggedIn: false,
				OAuth:      false,
				Provider:   "",
			}, nil
		}
		return types.UserContext{
			Email:      sessionValue,
			IsLoggedIn: true,
			OAuth:      false,
			Provider:   "",
		}, nil
	}

	provider := hooks.Providers.GetProvider(sessionType)

	if provider == nil {
		return types.UserContext{
			Email:      "",
			IsLoggedIn: false,
			OAuth:      false,
			Provider:   "",
		}, nil
	}

	if !hooks.Auth.EmailWhitelisted(sessionValue) {
		session.Delete("tinyauth_sid")
		session.Save()
		return types.UserContext{
			Email:      "",
			IsLoggedIn: false,
			OAuth:      false,
			Provider:   "",
		}, nil
	}

	return types.UserContext{
		Email:      sessionValue,
		IsLoggedIn: true,
		OAuth:      true,
		Provider:   sessionType,
	}, nil
}
