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

	log.Debug().Msg("Setting up router")
	router := gin.New()
	router.Use(zerolog())
	log.Debug().Msg("Setting up assets")
	dist, distErr := fs.Sub(assets.Assets, "dist")

	if distErr != nil {
		log.Fatal().Err(distErr).Msg("Failed to get UI assets")
	}

	log.Debug().Msg("Setting up file server")
	fileServer := http.FileServer(http.FS(dist))
	log.Debug().Msg("Setting up cookie store")
	store := cookie.NewStore([]byte(api.Config.Secret))

	log.Debug().Msg("Getting domain")
	domain, domainErr := utils.GetRootURL(api.Config.AppURL)

	if domainErr != nil {
		log.Fatal().Err(domainErr).Msg("Failed to get domain")
		os.Exit(1)
	}

	log.Info().Str("domain", domain).Msg("Using domain for cookies")

	api.Domain = fmt.Sprintf(".%s", domain)

	store.Options(sessions.Options{
		Domain:   api.Domain,
		Path:     "/",
		HttpOnly: true,
		Secure:   api.Config.CookieSecure,
		MaxAge:   api.Config.CookieExpiry,
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
		log.Debug().Msg("Checking auth")
		userContext := api.Hooks.UseUserContext(c)

		if userContext.IsLoggedIn {
			log.Debug().Msg("Authenticated")
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

		log.Debug().Interface("queries", queries).Msg("Redirecting to login")

		if queryErr != nil {
			log.Error().Err(queryErr).Msg("Failed to build query")
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
			log.Error().Err(err).Msg("Failed to bind JSON")
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Bad Request",
			})
			return
		}

		log.Debug().Interface("login", login).Msg("Got login request")

		user := api.Auth.GetUser(login.Username)

		if user == nil {
			log.Debug().Str("username", login.Username).Msg("User not found")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}

		if !api.Auth.CheckPassword(*user, login.Password) {
			log.Debug().Str("username", login.Username).Msg("Password incorrect")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Unauthorized",
			})
			return
		}

		log.Debug().Msg("Password correct, logging in")

		api.Auth.CreateSessionCookie(c, &types.SessionCookie{
			Username: login.Username,
			Provider: "username",
		})

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Logged in",
		})
	})

	api.Router.POST("/api/logout", func(c *gin.Context) {
		api.Auth.DeleteSessionCookie(c)

		log.Debug().Msg("Cleaning up redirect cookie")

		c.SetCookie("tinyauth_redirect_uri", "", -1, "/", api.Domain, api.Config.CookieSecure, true)

		c.JSON(200, gin.H{
			"status":  200,
			"message": "Logged out",
		})
	})

	api.Router.GET("/api/status", func(c *gin.Context) {
		log.Debug().Msg("Checking status")
		userContext := api.Hooks.UseUserContext(c)

		configuredProviders := api.Providers.GetConfiguredProviders()

		if api.Auth.UserAuthConfigured() {
			configuredProviders = append(configuredProviders, "username")
		}

		if !userContext.IsLoggedIn {
			log.Debug().Msg("Unauthenticated")
			c.JSON(200, gin.H{
				"status":              200,
				"message":             "Unauthenticated",
				"username":            "",
				"isLoggedIn":          false,
				"oauth":               false,
				"provider":            "",
				"configuredProviders": configuredProviders,
				"disableContinue":     api.Config.DisableContinue,
			})
			return
		}

		log.Debug().Interface("userContext", userContext).Strs("configuredProviders", configuredProviders).Bool("disableContinue", api.Config.DisableContinue).Msg("Authenticated")

		c.JSON(200, gin.H{
			"status":              200,
			"message":             "Authenticated",
			"username":            userContext.Username,
			"isLoggedIn":          userContext.IsLoggedIn,
			"oauth":               userContext.OAuth,
			"provider":            userContext.Provider,
			"configuredProviders": configuredProviders,
			"disableContinue":     api.Config.DisableContinue,
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
			log.Error().Err(bindErr).Msg("Failed to bind URI")
			c.JSON(400, gin.H{
				"status":  400,
				"message": "Bad Request",
			})
			return
		}

		log.Debug().Interface("request", request).Msg("Got OAuth request")

		provider := api.Providers.GetProvider(request.Provider)

		if provider == nil {
			c.JSON(404, gin.H{
				"status":  404,
				"message": "Not Found",
			})
			return
		}

		log.Debug().Str("provider", request.Provider).Msg("Got provider")

		authURL := provider.GetAuthURL()

		log.Debug().Str("authURL", authURL).Msg("Got auth URL")

		redirectURI := c.Query("redirect_uri")

		if redirectURI != "" {
			log.Debug().Str("redirectURI", redirectURI).Msg("Setting redirect cookie")
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

		if handleApiError(c, "Failed to bind URI", bindErr) {
			return
		}

		log.Debug().Interface("providerName", providerName).Msg("Got provider name")

		code := c.Query("code")

		if code == "" {
			log.Error().Msg("No code provided")
			c.Redirect(http.StatusPermanentRedirect, "/error")
			return
		}

		log.Debug().Str("code", code).Msg("Got code")

		provider := api.Providers.GetProvider(providerName.Provider)

		log.Debug().Str("provider", providerName.Provider).Msg("Got provider")

		if provider == nil {
			c.Redirect(http.StatusPermanentRedirect, "/not-found")
			return
		}

		token, tokenErr := provider.ExchangeToken(code)

		log.Debug().Str("token", token).Msg("Got token")

		if handleApiError(c, "Failed to exchange token", tokenErr) {
			return
		}

		email, emailErr := api.Providers.GetUser(providerName.Provider)

		log.Debug().Str("email", email).Msg("Got email")

		if handleApiError(c, "Failed to get user", emailErr) {
			return
		}

		if !api.Auth.EmailWhitelisted(email) {
			log.Warn().Str("email", email).Msg("Email not whitelisted")
			unauthorizedQuery, unauthorizedQueryErr := query.Values(types.UnauthorizedQuery{
				Username: email,
			})
			if handleApiError(c, "Failed to build query", unauthorizedQueryErr) {
				return
			}
			c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/unauthorized?%s", api.Config.AppURL, unauthorizedQuery.Encode()))
		}

		log.Debug().Msg("Email whitelisted")

		api.Auth.CreateSessionCookie(c, &types.SessionCookie{
			Username: email,
			Provider: providerName.Provider,
		})

		redirectURI, redirectURIErr := c.Cookie("tinyauth_redirect_uri")

		if redirectURIErr != nil {
			c.JSON(200, gin.H{
				"status":  200,
				"message": "Logged in",
			})
		}

		log.Debug().Str("redirectURI", redirectURI).Msg("Got redirect URI")

		c.SetCookie("tinyauth_redirect_uri", "", -1, "/", api.Domain, api.Config.CookieSecure, true)

		redirectQuery, redirectQueryErr := query.Values(types.LoginQuery{
			RedirectURI: redirectURI,
		})

		log.Debug().Interface("redirectQuery", redirectQuery).Msg("Got redirect query")

		if handleApiError(c, "Failed to build query", redirectQueryErr) {
			return
		}

		c.Redirect(http.StatusPermanentRedirect, fmt.Sprintf("%s/continue?%s", api.Config.AppURL, redirectQuery.Encode()))
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

func handleApiError(c *gin.Context, msg string, err error) bool {
	if err != nil {
		log.Error().Err(err).Msg(msg)
		c.Redirect(http.StatusPermanentRedirect, "/error")
		return true
	}
	return false
}
