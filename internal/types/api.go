package types

// LoginQuery is the query parameters for the login endpoint
type LoginQuery struct {
	RedirectURI string `url:"redirect_uri"`
}

// LoginRequest is the request body for the login endpoint
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// OAuthRequest is the request for the OAuth endpoint
type OAuthRequest struct {
	Provider string `uri:"provider" binding:"required"`
}

// UnauthorizedQuery is the query parameters for the unauthorized endpoint
type UnauthorizedQuery struct {
	Username string `url:"username"`
	Resource string `url:"resource"`
}

// TailscaleQuery is the query parameters for the tailscale endpoint
type TailscaleQuery struct {
	Code int `url:"code"`
}

// Proxy is the uri parameters for the proxy endpoint
type Proxy struct {
	Proxy string `uri:"proxy" binding:"required"`
}

// User Context response is the response for the user context endpoint
type UserContextResponse struct {
	Status      int    `json:"status"`
	Message     string `json:"message"`
	IsLoggedIn  bool   `json:"isLoggedIn"`
	Username    string `json:"username"`
	Provider    string `json:"provider"`
	Oauth       bool   `json:"oauth"`
	TotpPending bool   `json:"totpPending"`
}

// Totp request is the request for the totp endpoint
type TotpRequest struct {
	Code string `json:"code"`
}
