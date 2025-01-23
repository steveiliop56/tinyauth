package hooks

import (
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
	oauthProviderCookie := session.Get("tinyauth_oauth_provider")

	if sessionCookie == nil {
		return types.UserContext{
			Email:      "",
			IsLoggedIn: false,
			OAuth:      false,
			Provider:   "",
		}, nil
	}

	email, emailOk := sessionCookie.(string)
	provider, providerOk := oauthProviderCookie.(string)

	if provider == "" || !providerOk {
		if !emailOk {
			return types.UserContext{
				Email:      "",
				IsLoggedIn: false,
				OAuth:      false,
				Provider:   "",
			}, nil
		}
		user := hooks.Auth.GetUser(email)
		if user == nil {
			return types.UserContext{
				Email:      "",
				IsLoggedIn: false,
				OAuth:      false,
				Provider:   "",
			}, nil
		}
		return types.UserContext{
			Email:      email,
			IsLoggedIn: true,
			OAuth:      false,
			Provider:   "",
		}, nil
	}

	oauthEmail, oauthEmailErr := hooks.Providers.GetUser(provider)

	if oauthEmailErr != nil {
		return types.UserContext{
			Email:      "",
			IsLoggedIn: false,
			OAuth:      false,
			Provider:   "",
		}, nil
	}

	return types.UserContext{
		Email:      oauthEmail,
		IsLoggedIn: true,
		OAuth:      true,
		Provider:   provider,
	}, nil
}
