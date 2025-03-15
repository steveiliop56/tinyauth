package types

// API config is the configuration for the API
type APIConfig struct {
	Port            int
	Address         string
	Secret          string
	AppURL          string
	CookieSecure    bool
	SessionExpiry   int
	DisableContinue bool
	GenericName     string
	Title           string
	Domain          string
}
