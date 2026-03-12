package controller_test

import (
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/controller"
)

// Testing suite

type ControllerTest[T any] struct {
	ctrlSetup func(router *gin.RouterGroup) T
}

func NewControllerTest[T any](setup func(router *gin.RouterGroup) T) *ControllerTest[T] {
	return &ControllerTest[T]{ctrlSetup: setup}
}

func (ctrlt *ControllerTest[T]) newEngine(middlewares []gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)

	engine := gin.New()

	for _, mw := range middlewares {
		engine.Use(mw)
	}

	return engine
}

func (ctrlrt *ControllerTest[T]) newControllerInstance(engine *gin.Engine) T {
	ctrl := ctrlrt.ctrlSetup(engine.Group("/api"))
	return ctrl
}

func (ctrlt *ControllerTest[T]) RequestWithMiddleware(http *http.Request, middlewares []gin.HandlerFunc) *httptest.ResponseRecorder {
	engine := ctrlt.newEngine(middlewares)
	ctrlt.newControllerInstance(engine)
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, http)
	return recorder
}

func (ctrlt *ControllerTest[T]) Request(http *http.Request) *httptest.ResponseRecorder {
	return ctrlt.RequestWithMiddleware(http, nil)
}

// Controller configs

var contextControllerCfg = controller.ContextControllerConfig{
	Providers: []controller.Provider{
		{
			Name:  "Local",
			ID:    "local",
			OAuth: false,
		},
		{
			Name:  "Google",
			ID:    "google",
			OAuth: true,
		},
	},
	Title:                 "Tinyauth Testing",
	AppURL:                "http://tinyauth.example.com:3000",
	CookieDomain:          "example.com",
	ForgotPasswordMessage: "Foo bar",
	BackgroundImage:       "/background.jpg",
	OAuthAutoRedirect:     "google",
	WarningsEnabled:       true,
}

var testContext = config.UserContext{
	Username:    "user",
	Name:        "User",
	Email:       "user@example.com",
	IsLoggedIn:  false,
	IsBasicAuth: false,
	OAuth:       false,
	Provider:    "",
	TotpPending: false,
	OAuthGroups: "group1,group2",
	TotpEnabled: false,
	OAuthName:   "test",
	OAuthSub:    "test",
	LdapGroups:  "group1,group2",
}
