package hooks

import (
	"tinyauth/internal/auth"
	"tinyauth/internal/types"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func UseUserContext(c *gin.Context, userList types.UserList) (types.UserContext) {
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

	user := auth.FindUser(userList, username)

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