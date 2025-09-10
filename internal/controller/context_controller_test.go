package controller_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"tinyauth/internal/config"
	"tinyauth/internal/controller"

	"github.com/gin-gonic/gin"
	"gotest.tools/v3/assert"
)

var controllerCfg = controller.ContextControllerConfig{
	ConfiguredProviders:   []string{"github", "google", "generic"},
	Title:                 "Test App",
	GenericName:           "Generic",
	AppURL:                "http://localhost:8080",
	ForgotPasswordMessage: "Contact admin to reset your password.",
	BackgroundImage:       "/assets/bg.jpg",
	OAuthAutoRedirect:     "google",
}

var userContext = config.UserContext{
	Username:    "testuser",
	Name:        "testuser",
	Email:       "test@example.com",
	IsLoggedIn:  true,
	OAuth:       false,
	Provider:    "username",
	TotpPending: false,
	OAuthGroups: "",
	TotpEnabled: false,
}

func setupContextController(middlewares *[]gin.HandlerFunc) (*gin.Engine, *httptest.ResponseRecorder) {
	// Setup
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	recorder := httptest.NewRecorder()

	if middlewares != nil {
		for _, m := range *middlewares {
			router.Use(m)
		}
	}

	group := router.Group("/api")

	ctrl := controller.NewContextController(controllerCfg, group)
	ctrl.SetupRoutes()

	return router, recorder
}

func TestAppContextHandler(t *testing.T) {
	expectedRes := controller.AppContextResponse{
		Status:                200,
		Message:               "Success",
		ConfiguredProviders:   controllerCfg.ConfiguredProviders,
		Title:                 controllerCfg.Title,
		GenericName:           controllerCfg.GenericName,
		AppURL:                controllerCfg.AppURL,
		ForgotPasswordMessage: controllerCfg.ForgotPasswordMessage,
		BackgroundImage:       controllerCfg.BackgroundImage,
		OAuthAutoRedirect:     controllerCfg.OAuthAutoRedirect,
	}

	router, recorder := setupContextController(nil)
	req := httptest.NewRequest("GET", "/api/context/app", nil)
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 200, recorder.Code)

	var ctrlRes controller.AppContextResponse

	err := json.Unmarshal(recorder.Body.Bytes(), &ctrlRes)

	assert.NilError(t, err)
	assert.DeepEqual(t, expectedRes, ctrlRes)
}

func TestUserContextHandler(t *testing.T) {
	expectedRes := controller.UserContextResponse{
		Status:      200,
		Message:     "Success",
		IsLoggedIn:  userContext.IsLoggedIn,
		Username:    userContext.Username,
		Name:        userContext.Name,
		Email:       userContext.Email,
		Provider:    userContext.Provider,
		OAuth:       userContext.OAuth,
		TotpPending: userContext.TotpPending,
	}

	// Test with context
	router, recorder := setupContextController(&[]gin.HandlerFunc{
		func(c *gin.Context) {
			c.Set("context", &userContext)
			c.Next()
		},
	})

	req := httptest.NewRequest("GET", "/api/context/user", nil)
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 200, recorder.Code)

	var ctrlRes controller.UserContextResponse

	err := json.Unmarshal(recorder.Body.Bytes(), &ctrlRes)

	assert.NilError(t, err)
	assert.DeepEqual(t, expectedRes, ctrlRes)

	// Test no context
	expectedRes = controller.UserContextResponse{
		Status:     401,
		Message:    "Unauthorized",
		IsLoggedIn: false,
	}

	router, recorder = setupContextController(nil)
	req = httptest.NewRequest("GET", "/api/context/user", nil)
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 200, recorder.Code)

	err = json.Unmarshal(recorder.Body.Bytes(), &ctrlRes)

	assert.NilError(t, err)
	assert.DeepEqual(t, expectedRes, ctrlRes)
}
