package api

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"
	"tinyauth/internal/assets"
	"tinyauth/internal/auth"
	"tinyauth/internal/types"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/rs/zerolog/log"
)

func Run(config types.Config, users types.UserList) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(zerolog())
	dist, distErr := fs.Sub(assets.Assets, "dist")

	if distErr != nil {
		log.Fatal().Err(distErr).Msg("Failed to get UI assets")
		os.Exit(1)
	}

	fileServer := http.FileServer(http.FS(dist))
	store := cookie.NewStore([]byte(config.Secret))

	domain := strings.Split(config.RootURL, "://")[1]

	store.Options(sessions.Options{
		Domain: fmt.Sprintf(".%s", domain),
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

		if value != nil {
			usernameString, ok := value.(string)
			if ok {
				if auth.FindUser(users, usernameString) != nil {
					c.JSON(200, gin.H{
						"status": 200,
						"message": "Authorized",
					})
					return
				}
			}
		}

		uri := c.Request.Header.Get("X-Forwarded-Uri")
		proto := c.Request.Header.Get("X-Forwarded-Proto")
		host := c.Request.Header.Get("X-Forwarded-Host")
		queries, queryErr := query.Values(types.LoginQuery{
			RedirectURI: fmt.Sprintf("%s://%s%s", proto, host, uri),
		})

		if queryErr != nil {
			c.JSON(501, gin.H{
				"status": 501,
				"message": "Internal Server Error",
			})
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/?%s", config.AppURL, queries.Encode()))
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

		user := auth.FindUser(users, login.Username)

		if user == nil {
			c.JSON(401, gin.H{
				"status": 401,
				"message": "Unauthorized",
			})
			return
		}

		if !auth.CheckPassword(*user, login.Password) {
			c.JSON(401, gin.H{
				"status": 401,
				"message": "Unauthorized",
			})
			return
		}

		session := sessions.Default(c)
		session.Set("tinyauth", user.Username)
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

		if value != nil {
			usernameString, ok := value.(string)
			if ok {
				if auth.FindUser(users, usernameString) != nil {
					c.JSON(200, gin.H{
						"status": 200,
						"isLoggedIn": true,
						"username": usernameString,
					})
					return
				}
			}
		}

		c.JSON(200, gin.H{
			"status": 200,
			"isLoggedIn": false,
			"username": "",
		})
	})

	router.Run(fmt.Sprintf("%s:%d", config.Address, config.Port))
}

func zerolog() gin.HandlerFunc {
	return func(c *gin.Context) {
		tStart := time.Now()

		c.Next()

		code := c.Writer.Status()
		address := c.Request.RemoteAddr
		method := c.Request.Method
		path := c.Request.URL.Path
		
		latency := time.Since(tStart).String()

		switch {
			case code >= 200 && code < 300:
				log.Info().Str("method", method).Str("path", path).Str("address", address).Int("status", code).Str("latency", latency).Msg("Request")
			case code >= 300 && code < 400:
				log.Warn().Str("method", method).Str("path", path).Str("address", address).Int("status", code).Str("latency", latency).Msg("Request")
			case code >= 400:
				log.Error().Str("method", method).Str("path", path).Str("address", address).Int("status", code).Str("latency", latency).Msg("Request")
		}
	}
}