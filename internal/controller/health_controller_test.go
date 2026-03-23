package controller_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/steveiliop56/tinyauth/internal/controller"
)

func TestHealthController(t *testing.T) {
	tests := []struct {
		description string
		path        string
		method      string
		expected    string
	}{
		{
			description: "Ensure health endpoint returns 200 OK",
			path:        "/api/healthz",
			method:      "GET",
			expected: func() string {
				expectedHealthResponse := map[string]any{
					"status":  200,
					"message": "Healthy",
				}

				bytes, err := json.Marshal(expectedHealthResponse)

				if err != nil {
					t.Fatalf("Failed to marshal expected response: %v", err)
				}

				return string(bytes)
			}(),
		},
		{
			description: "Ensure health endpoint returns 200 OK for HEAD request",
			path:        "/api/healthz",
			method:      "HEAD",
			expected: func() string {
				expectedHealthResponse := map[string]any{
					"status":  200,
					"message": "Healthy",
				}

				bytes, err := json.Marshal(expectedHealthResponse)

				if err != nil {
					t.Fatalf("Failed to marshal expected response: %v", err)
				}

				return string(bytes)
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			router := gin.Default()
			group := router.Group("/api")
			gin.SetMode(gin.TestMode)

			healthController := controller.NewHealthController(group)
			healthController.SetupRoutes()

			recorder := httptest.NewRecorder()

			request, err := http.NewRequest(test.method, test.path, nil)

			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			router.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("Expected status code 200, got %d", recorder.Code)
			}

			if recorder.Body.String() != test.expected {
				t.Fatalf("Expected response body %s, got %s", test.expected, recorder.Body.String())
			}
		})
	}
}
