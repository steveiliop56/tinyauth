package api

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"tinyauth/internal/assets"
	"tinyauth/internal/types"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
)

func Run() {
	router := gin.Default()
	dist, _ := fs.Sub(assets.Assets, "dist")
	fileServer := http.FileServer(http.FS(dist))
	store := cookie.NewStore([]byte("secret"))
	store.Options(sessions.Options{
		Domain: ".dev.local",
		Path: "/",
	})
  	router.Use(sessions.Sessions("tinyauth", store))

	router.Use(func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/api") {
			_, err := fs.Stat(dist, strings.TrimPrefix(c.Request.URL.Path, "/"))
			if os.IsNotExist(err) {
				c.Request.URL.Path = "/"
			}
			fileServer.ServeHTTP(c.Writer, c.Request)
			c.Abort()
		}
	})

	router.GET("/api/auth", func (c *gin.Context) {
		session := sessions.Default(c)
		value := session.Get("tinyauth")
		
		if value == nil || value != "true" {
			uri := c.Request.Header.Get("X-Forwarded-Uri")
			proto := c.Request.Header.Get("X-Forwarded-Proto")
			host := c.Request.Header.Get("X-Forwarded-Host")
			queries := types.LoginQuery{
				RedirectURI: fmt.Sprintf("%s://%s%s", proto, host, uri),
			}
			values, _ := query.Values(queries)
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("http://tinyauth.dev.local?%s", values.Encode()))
		}

		c.JSON(200, gin.H{
			"status": 200,
			"message": "Authorized",
		})
	})

	router.POST("/api/login", func (c *gin.Context) {
		var login types.LoginRequest

		err := c.BindJSON(&login)

		if err != nil {
			c.JSON(400, gin.H{
				"status": 400,
				"message": "Bad Request",
			})
			return
		}

		if login.Email != "user@example.com" || login.Password != "password" {
			c.JSON(401, gin.H{
				"status": 401,
				"message": "Unauthorized",
			})
			return
		}

		session := sessions.Default(c)
		session.Set("tinyauth", "true")
		session.Save()

		c.JSON(200, gin.H{
			"status": 200,
			"message": "Logged in",
		})
	})

	router.POST("/api/logout", func (c *gin.Context) {
		session := sessions.Default(c)
		session.Delete("tinyauth")
		session.Save()

		c.JSON(200, gin.H{
			"status": 200,
			"message": "Logged out",
		})
	})

	router.GET("/api/status", func (c *gin.Context) {
		session := sessions.Default(c)
		value := session.Get("tinyauth")

		if value == nil || value != "true" {
			c.JSON(200, gin.H{
				"status": 200,
				"isLoggedIn": false,
			})
			return
		}

		c.JSON(200, gin.H{
			"status": 200,
			"isLoggedIn": true,
		})
	})

	router.Run(":3000")
}