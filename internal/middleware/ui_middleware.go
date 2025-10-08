package middleware

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"
	"tinyauth/internal/assets"

	"github.com/gin-gonic/gin"
)

type UIMiddleware struct {
	uiFs         fs.FS
	uiFileServer http.Handler
}

func NewUIMiddleware() *UIMiddleware {
	return &UIMiddleware{}
}

func (m *UIMiddleware) Init() error {
	ui, err := fs.Sub(assets.FrontendAssets, "dist")

	if err != nil {
		return err
	}

	m.uiFs = ui
	m.uiFileServer = http.FileServerFS(ui)

	return nil
}

func (m *UIMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := strings.TrimPrefix(c.Request.URL.Path, "/")

		switch strings.SplitN(path, "/", 2)[0] {
		case "api":
			c.Next()
			return
		case "resources":
			c.Next()
			return
		default:
			_, err := fs.Stat(m.uiFs, path)

			// Enough for one authentication flow
			maxAge := 15 * time.Minute

			if os.IsNotExist(err) {
				c.Request.URL.Path = "/"
			} else if strings.HasPrefix(path, "assets/") {
				// assets are named with a hash and can be cached for a long time
				maxAge = 30 * 24 * time.Hour
			}

			c.Writer.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(maxAge.Seconds())))
			m.uiFileServer.ServeHTTP(c.Writer, c.Request)
			c.Abort()
			return
		}
	}
}
