package controller_test

import (
	"net/http/httptest"
	"os"
	"testing"

	"github.com/steveiliop56/tinyauth/internal/controller"

	"github.com/gin-gonic/gin"
	"gotest.tools/v3/assert"
)

func TestResourcesHandler(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	router := gin.New()
	group := router.Group("/")

	ctrl := controller.NewResourcesController(controller.ResourcesControllerConfig{
		ResourcesDir: "/tmp/tinyauth",
	}, group)
	ctrl.SetupRoutes()

	// Create test data
	err := os.Mkdir("/tmp/tinyauth", 0755)
	assert.NilError(t, err)
	defer os.RemoveAll("/tmp/tinyauth")

	file, err := os.Create("/tmp/tinyauth/test.txt")
	assert.NilError(t, err)

	_, err = file.WriteString("This is a test file.")
	assert.NilError(t, err)
	file.Close()

	// Test existing file
	req := httptest.NewRequest("GET", "/resources/test.txt", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 200, recorder.Code)
	assert.Equal(t, "This is a test file.", recorder.Body.String())

	// Test non-existing file
	req = httptest.NewRequest("GET", "/resources/nonexistent.txt", nil)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 404, recorder.Code)

	// Test directory traversal attack
	req = httptest.NewRequest("GET", "/resources/../etc/passwd", nil)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	assert.Equal(t, 404, recorder.Code)
}
