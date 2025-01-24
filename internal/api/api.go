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
	"tinyauth/internal/hooks"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
	"github.com/rs/zerolog/log"
)

func NewAPI(config types.APIConfig, hooks *hooks.Hooks, auth *auth.Auth, providers *providers.Providers) *API {
	return &API{
		Config:    config,
		Hooks:     hooks,
		Auth:      auth,
		Providers: providers,
	}
}

type API struct {
	Config    types.APIConfig
	Router    *gin.Engine
	Hooks     *hooks.Hooks
	Auth      *auth.Auth
	Providers *providers.Providers
	Domain    string
}

func (api *API) Init() {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(zerolog())
	dist, distErr := fs.Sub(assets.Assets, "dist")

	if distErr != nil {
		log.Fatal().Err(distErr).Msg("Failed to get UI assets")
		os.Exit(1)
	}

	fileServer := http.FileServer(http.FS(dist))
	store := cookie.NewStore([]byte(api.Config.Secret))

	domain, domainErr := utils.GetRootURL(api.Config.AppURL)

	log.Info().Str("domain", domain).Msg("Using domain for cookies")

	if domainErr != nil {
		log.Fatal().Err(domainErr).Msg("Failed to get domain")
		os.Exit(1)
	}

	var isSecure bool

	if api.Config.CookieSecure {
		isSecure = true
	} else {
		isSecure = false
	}

	api.Domain = fmt.Sprintf(".%s", domain)

	store.Options(sessions.Options{
		Domain:   api.Domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
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

	api.Router = router
}

func (api *API) SetupRoutes() {
	api.Router.GET("/api/auth", func(c *gin.Context) {
		userContext, userContextErr := api.Hooks.UseUserContext(c)

		if userContextErr != nil {
			c.JSON(500, gin.H{
				"status":  500,
				"message": "Internal Server Error",
			})
			return
		}

		if userContext.IsLoggedIn {
			c.JSON(200, gin.H{
				"status":  200,
				"message": "Authenticated",
			})
			return
		}

		uri := c.Request.Header.Get("X-Forwarded-Uri")
		proto := c.Request.Header.Get("X-Forwarded-Proto")
		host := c.Request.Header.Get("X-Forwarded-Host")
		queries, queryErr := query.Values(types.LoginQuery{
			RedirectURI: fmt.Sprintf("%s://%s%s", proto, host, uri),
		})

		if queryErr != nil {
			c.JSON(501, gin.H{
				"status":  501,
				"message": "Internal Server Error",
			})
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/?%s", api.Config.AppURL, queries.Encode()))
	})

	api.Router.POST("/api/login", func(c *gin.Context) {
		var login types.LoginRequest

		err := c.BindJSON(&login)

		if err != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Bad Request",
			})
			return
		}

		user := api.Auth.GetUser(login.Email)

		if user == nil {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}

		if !api.Auth.CheckPassword(*user, login.Password) {
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}

		session := sessions.Default(c)
		session.Set("tinyauth_sid", fmt.Sprintf("email:%s", login.Email))
		session.Save()

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Logged in",
		})
	})

	api.Router.POST("/api/logout", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Delete("tinyauth_sid")
		session.Save()

		c.SetCookie("tinyauth_redirect_uri", "", -1, "/", api.Domain, api.Config.CookieSecure, true)

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Logged out",
		})
	})

	api.Router.GET("/api/status", func(c *gin.Context) {
		userContext, userContextErr := api.Hooks.UseUserContext(c)

		if userContextErr != nil {
			c.JSON(500, gin.H{
				"status":  500,
				"message": "Internal Server Error",
			})
			return
		}

		if !userContext.IsLoggedIn {
			c.JSON(200, gin.H{
				"status":              200,
				"message":             "Unauthenticated",
				"email":               "",
				"isLoggedIn":          false,
				"oauth":               false,
				"provider":            "",
				"configuredProviders": api.Providers.GetConfiguredProviders(),
			})
			return
		}

		c.JSON(200, gin.H{
			"status":              200,
			"message":             "Authenticated",
			"email":               userContext.Email,
			"isLoggedIn":          userContext.IsLoggedIn,
			"oauth":               userContext.OAuth,
			"provider":            userContext.Provider,
			"configuredProviders": api.Providers.GetConfiguredProviders(),
		})
	})

	api.Router.GET("/api/healthcheck", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  200,
			"message": "OK",
		})
	})

	api.Router.GET("/api/oauth/url/:provider", func(c *gin.Context) {
		var request types.OAuthRequest

		bindErr := c.BindUri(&request)

		if bindErr != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Bad Request",
			})
			return
		}

		provider := api.Providers.GetProvider(request.Provider)

		if provider == nil {
			c.JSON(404, gin.H{
				"status":  404,
				"message": "Not Found",
			})
			return
		}

		authURL := provider.GetAuthURL()

		redirectURI := c.Query("redirect_uri")

		if redirectURI != "" {
			c.SetCookie("tinyauth_redirect_uri", redirectURI, 3600, "/", api.Domain, api.Config.CookieSecure, true)
		}

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Ok",
			"url":     authURL,
		})
	})

	api.Router.GET("/api/oauth/callback/:provider", func(c *gin.Context) {
		var providerName types.OAuthRequest

		bindErr := c.BindUri(&providerName)

		if bindErr != nil {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Bad Request",
			})
			return
		}

		code := c.Query("code")

		if code == "" {
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Bad Request",
			})
			return
		}

		provider := api.Providers.GetProvider(providerName.Provider)

		if provider == nil {
			c.JSON(404, gin.H{
				"status":  404,
				"message": "Not Found",
			})
			return
		}

		token, tokenErr := provider.ExchangeToken(code)

		if tokenErr != nil {
			c.JSON(500, gin.H{
				"status":  500,
				"message": "Internal Server Error",
			})
			return
		}

		session := sessions.Default(c)
		session.Set("tinyauth_sid", fmt.Sprintf("%s:%s", providerName.Provider, token))
		session.Save()

		redirectURI, redirectURIErr := c.Cookie("tinyauth_redirect_uri")

		if redirectURIErr != nil {
			c.JSON(200, gin.H{
				"status":  200,
				"message": "Logged in",
			})
		}

		c.SetCookie("tinyauth_redirect_uri", "", -1, "/", api.Domain, api.Config.CookieSecure, true)

		queries, queryErr := query.Values(types.LoginQuery{
			RedirectURI: redirectURI,
		})

		if queryErr != nil {
			c.JSON(501, gin.H{
				"status":  501,
				"message": "Internal Server Error",
			})
			return
		}

		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/continue?%s", api.Config.AppURL, queries.Encode()))
	})
}

func (api *API) Run() {
	log.Info().Str("address", api.Config.Address).Int("port", api.Config.Port).Msg("Starting server")
	api.Router.Run(fmt.Sprintf("%s:%d", api.Config.Address, api.Config.Port))
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
