package middleware

import (
	"io/fs"
	"net/http"
	"os"
	"strings"
	"tinyauth/internal/assets"

	"github.com/gin-gonic/gin"
)

type UIMiddleware struct {
	UIFS         fs.FS
	UIFileServer http.Handler
}

func NewUIMiddleware() *UIMiddleware {
	return &UIMiddleware{}
}

func (m *UIMiddleware) Init() error {
	ui, err := fs.Sub(assets.FrontendAssets, "dist")

	if err != nil {
		return err
	}

	m.UIFS = ui
	m.UIFileServer = http.FileServer(http.FS(ui))

	return nil
}

func (m *UIMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch strings.Split(c.Request.URL.Path, "/")[1] {
		case "api":
			c.Next()
			return
		case "resources":
			c.Next()
			return
		default:
			_, err := fs.Stat(m.UIFS, strings.TrimPrefix(c.Request.URL.Path, "/"))

			if os.IsNotExist(err) {
				c.Request.URL.Path = "/"
			}

			m.UIFileServer.ServeHTTP(c.Writer, c.Request)
			c.Abort()
			return
		}
	}
}
