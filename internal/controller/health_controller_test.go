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

func TestHealthController(t *testing.T) {
	// Controller setup
	suite := NewControllerTest(func(router *gin.RouterGroup) *controller.HealthController {
		ctrl := controller.NewHealthController(router)
		ctrl.SetupRoutes()
		return ctrl
	})

	expected, err := json.Marshal(map[string]any{
		"status":  200,
		"message": "Healthy",
	})
	assert.NilError(t, err)

	// Test we are healthy with GET
	req, err := http.NewRequest("GET", "/api/healthz", nil)
	assert.NilError(t, err)

	resp := suite.Request(req)

	assert.Equal(t, http.StatusOK, resp.Code)
	bytes, err := io.ReadAll(resp.Body)
	assert.NilError(t, err)
	assert.DeepEqual(t, bytes, expected)

	// Test we are healthy with HEAD
	req, err = http.NewRequest("HEAD", "/api/healthz", nil)
	assert.NilError(t, err)

	resp = suite.Request(req)

	assert.Equal(t, http.StatusOK, resp.Code)
	bytes, err = io.ReadAll(resp.Body)
	assert.NilError(t, err)
	assert.DeepEqual(t, expected, bytes)
}
