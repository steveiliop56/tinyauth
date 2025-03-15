package types

// HealthCheckResponse is the response for the health check endpoint
type HealthCheckResponse struct {
	Status  int    `json:"status" example:"200"`
	Message string `json:"message" example:"Ok"`
}

// LogoutResponse is the response for the health check endpoint
type LogoutResponse struct {
	Status  int    `json:"status" example:"200"`
	Message string `json:"message" example:"Logged out"`
}
