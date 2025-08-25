package middlewares

import (
	"io/fs"
	"net/http"
	"os"
	"strings"
	"tinyauth/internal/assets"

	"github.com/gin-gonic/gin"
)

type UIMiddleware struct {
	UIFS                fs.FS
	UIFileServer        http.Handler
	ResourcesFileServer http.Handler
}

func NewUIMiddleware() (*UIMiddleware, error) {
	ui, err := fs.Sub(assets.Assets, "dist")

	if err != nil {
		return nil, err
	}

	uiFileServer := http.FileServer(http.FS(ui))
	resourcesFileServer := http.FileServer(http.Dir("/data/resources"))

	return &UIMiddleware{
		UIFS:                ui,
		UIFileServer:        uiFileServer,
		ResourcesFileServer: resourcesFileServer,
	}, nil
}

func (m UIMiddleware) Middlware() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch strings.Split(c.Request.URL.Path, "/")[1] {
		case "api":
			c.Next()
			return
		case "resources":
			_, err := os.Stat("/data/resources/" + strings.TrimPrefix(c.Request.URL.Path, "/resources/"))

			if os.IsNotExist(err) {
				c.Status(404)
				c.Abort()
				return
			}

			m.ResourcesFileServer.ServeHTTP(c.Writer, c.Request)
			c.Abort()
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
