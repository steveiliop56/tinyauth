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

func TestAppContextHandler(t *testing.T) {
	// Setup
	controllerCfg := controller.ContextControllerConfig{
		ConfiguredProviders:   []string{"github", "google", "generic"},
		Title:                 "Test App",
		GenericName:           "Generic",
		AppURL:                "http://localhost:8080",
		RootDomain:            "localhost",
		ForgotPasswordMessage: "Contact admin to reset your password.",
		BackgroundImage:       "/assets/bg.jpg",
		OAuthAutoRedirect:     "google",
	}

	expectedRes := controller.AppContextResponse{
		Status:                200,
		Message:               "Success",
		ConfiguredProviders:   controllerCfg.ConfiguredProviders,
		Title:                 controllerCfg.Title,
		GenericName:           controllerCfg.GenericName,
		AppURL:                controllerCfg.AppURL,
		RootDomain:            controllerCfg.RootDomain,
		ForgotPasswordMessage: controllerCfg.ForgotPasswordMessage,
		BackgroundImage:       controllerCfg.BackgroundImage,
		OAuthAutoRedirect:     controllerCfg.OAuthAutoRedirect,
	}

	gin.SetMode(gin.TestMode)
	router := gin.Default()
	group := router.Group("/api")
	recorder := httptest.NewRecorder()

	// Test
	ctrl := controller.NewContextController(controllerCfg, group)
	ctrl.SetupRoutes()

	req := httptest.NewRequest("GET", "/api/context/app", nil)
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 200, recorder.Code)

	var ctrlRes controller.AppContextResponse

	err := json.Unmarshal(recorder.Body.Bytes(), &ctrlRes)

	assert.NilError(t, err)
	assert.DeepEqual(t, expectedRes, ctrlRes)
}

func TestUserContextController(t *testing.T) {
	// Setup
	controllerCfg := controller.ContextControllerConfig{}

	userContext := config.UserContext{
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

	gin.SetMode(gin.TestMode)
	router := gin.Default()
	recorder := httptest.NewRecorder()

	router.Use(func(c *gin.Context) {
		c.Set("context", &userContext)
		c.Next()
	})

	group := router.Group("/api")

	// Test
	ctrl := controller.NewContextController(controllerCfg, group)
	ctrl.SetupRoutes()

	req := httptest.NewRequest("GET", "/api/context/user", nil)
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 200, recorder.Code)

	var ctrlRes controller.UserContextResponse

	err := json.Unmarshal(recorder.Body.Bytes(), &ctrlRes)

	assert.NilError(t, err)
	assert.DeepEqual(t, expectedRes, ctrlRes)
}
