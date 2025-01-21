package hooks

import (
	"tinyauth/internal/auth"
	"tinyauth/internal/types"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func NewHooks(auth *auth.Auth) *Hooks {
	return &Hooks{
		Auth: auth,
	}
}

type Hooks struct {
	Auth *auth.Auth
}

func (hooks *Hooks) UseUserContext(c *gin.Context) (types.UserContext) {
	session := sessions.Default(c)
	cookie := session.Get("tinyauth")

	if cookie == nil {
		return types.UserContext{
			Username: "",
			IsLoggedIn: false,
		}
	}

	username, ok := cookie.(string)

	if !ok {
		return types.UserContext{
			Username: "",
			IsLoggedIn: false,
		}
	}

	user := hooks.Auth.GetUser(username)

	if user == nil {
		return types.UserContext{
			Username: "",
			IsLoggedIn: false,
		}
	}

	return types.UserContext{
		Username: username,
		IsLoggedIn: true,
	}
}