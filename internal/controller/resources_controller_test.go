package controller_test

import (
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/steveiliop56/tinyauth/internal/controller"
	"github.com/stretchr/testify/assert"
)

func TestResourcesController(t *testing.T) {
	resourcesControllerCfg := controller.ResourcesControllerConfig{
		Path:    "/tmp/testfiles",
		Enabled: true,
	}

	type testCase struct {
		description string
		run         func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder)
	}

	tests := []testCase{
		{
			description: "Ensure resources endpoint returns 200 OK for existing file",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/resources/testfile.txt", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 200, recorder.Code)
				assert.Equal(t, "This is a test file.", recorder.Body.String())
			},
		},
		{
			description: "Ensure resources endpoint returns 404 Not Found for non-existing file",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/resources/nonexistent.txt", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 404, recorder.Code)
			},
		},
		{
			description: "Ensure resources controller denies path traversal",
			run: func(t *testing.T, router *gin.Engine, recorder *httptest.ResponseRecorder) {
				req := httptest.NewRequest("GET", "/resources/../somefile.txt", nil)
				router.ServeHTTP(recorder, req)

				assert.Equal(t, 404, recorder.Code)
			},
		},
	}

	err := os.MkdirAll(resourcesControllerCfg.Path, 0777)
	assert.NoError(t, err)

	testFilePath := resourcesControllerCfg.Path + "/testfile.txt"
	err = os.WriteFile(testFilePath, []byte("This is a test file."), 0777)
	assert.NoError(t, err)

	testFilePathParent := resourcesControllerCfg.Path + "/../somefile.txt"
	err = os.WriteFile(testFilePathParent, []byte("This file should not be accessible."), 0777)
	assert.NoError(t, err)

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()
			group := router.Group("/")
			gin.SetMode(gin.TestMode)

			resourcesController := controller.NewResourcesController(resourcesControllerCfg, group)
			resourcesController.SetupRoutes()

			recorder := httptest.NewRecorder()
			test.run(t, router, recorder)
		})
	}

	err = os.Remove(testFilePath)
	assert.NoError(t, err)

	err = os.Remove(testFilePathParent)
	assert.NoError(t, err)

	err = os.Remove(resourcesControllerCfg.Path)
	assert.NoError(t, err)
}
