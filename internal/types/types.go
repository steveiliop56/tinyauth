package types

type LoginQuery struct {
	RedirectURI string `url:"redirect_uri"`
}

type LoginRequest struct {
	Email string `json:"email"`
	Password string `json:"password"`
}