package middleware

import (
	"io/fs"
	"net/http"
	"os"
	"strings"
	"tinyauth/internal/assets"

	"github.com/gin-gonic/gin"
)

type UIMiddlewareConfig struct {
	ResourcesDir string
}

type UIMiddleware struct {
	Config              UIMiddlewareConfig
	UIFS                fs.FS
	UIFileServer        http.Handler
	ResourcesFileServer http.Handler
}

func NewUIMiddleware(config UIMiddlewareConfig) *UIMiddleware {
	return &UIMiddleware{
		Config: config,
	}
}

func (m *UIMiddleware) Init() error {
	ui, err := fs.Sub(assets.FontendAssets, "dist")

	if err != nil {
		return nil
	}

	m.UIFS = ui
	m.UIFileServer = http.FileServer(http.FS(ui))
	m.ResourcesFileServer = http.FileServer(http.Dir(m.Config.ResourcesDir))

	return nil
}

func (m *UIMiddleware) Name() string {
	return "UIMiddleware"
}

func (m *UIMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch strings.Split(c.Request.URL.Path, "/")[1] {
		case "api":
			c.Next()
			return
		case "resources":
			_, err := os.Stat(m.Config.ResourcesDir + strings.TrimPrefix(c.Request.URL.Path, "/resources/"))

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
