package controller_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/steveiliop56/tinyauth/internal/controller"
	"gotest.tools/v3/assert"
)

func TestUserContextController(t *testing.T) {
	// Controller setup
	suite := NewControllerTest(func(router *gin.RouterGroup) *controller.ContextController {
		ctrl := controller.NewContextController(contextControllerCfg, router)
		ctrl.SetupRoutes()
		return ctrl
	})

	// Test user context
	req, err := http.NewRequest("GET", "/api/context/user", nil)
	assert.NilError(t, err)

	ctx := testContext
	ctx.IsLoggedIn = true
	ctx.Provider = "local"

	expected, err := json.Marshal(controller.UserContextResponse{
		Status:      200,
		Message:     "Success",
		IsLoggedIn:  ctx.IsLoggedIn,
		Username:    ctx.Username,
		Name:        ctx.Name,
		Email:       ctx.Email,
		Provider:    ctx.Provider,
		OAuth:       ctx.OAuth,
		TotpPending: ctx.TotpPending,
		OAuthName:   ctx.OAuthName,
	})
	assert.NilError(t, err)

	resp := suite.RequestWithMiddleware(req, []gin.HandlerFunc{
		func(c *gin.Context) {
			c.Set("context", &ctx)
		},
	})

	assert.Equal(t, http.StatusOK, resp.Code)
	bytes, err := io.ReadAll(resp.Body)
	assert.NilError(t, err)
	assert.DeepEqual(t, expected, bytes)

	// Ensure user context is not available when not logged in
	req, err = http.NewRequest("GET", "/api/context/user", nil)
	assert.NilError(t, err)

	expected, err = json.Marshal(controller.UserContextResponse{
		Status:  http.StatusUnauthorized,
		Message: "Unauthorized",
	})
	assert.NilError(t, err)

	resp = suite.RequestWithMiddleware(req, nil)
	assert.Equal(t, 200, resp.Code)
	bytes, err = io.ReadAll(resp.Body)
	assert.NilError(t, err)
	assert.DeepEqual(t, expected, bytes)

	// Test app context
	req, err = http.NewRequest("GET", "/api/context/app", nil)
	assert.NilError(t, err)

	expected, err = json.Marshal(controller.AppContextResponse{
		Status:                200,
		Message:               "Success",
		Providers:             contextControllerCfg.Providers,
		Title:                 contextControllerCfg.Title,
		AppURL:                contextControllerCfg.AppURL,
		CookieDomain:          contextControllerCfg.CookieDomain,
		ForgotPasswordMessage: contextControllerCfg.ForgotPasswordMessage,
		BackgroundImage:       contextControllerCfg.BackgroundImage,
		OAuthAutoRedirect:     contextControllerCfg.OAuthAutoRedirect,
		WarningsEnabled:       contextControllerCfg.WarningsEnabled,
	})
	assert.NilError(t, err)

	resp = suite.RequestWithMiddleware(req, nil)

	assert.Equal(t, http.StatusOK, resp.Code)
	bytes, err = io.ReadAll(resp.Body)
	assert.NilError(t, err)
	assert.DeepEqual(t, expected, bytes)
}
