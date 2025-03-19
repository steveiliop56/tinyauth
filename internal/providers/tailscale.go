package providers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

// The tailscale email is the loginName
type TailscaleUser struct {
	LoginName string `json:"loginName"`
}

// The response from the tailscale user info endpoint
type TailscaleUserInfoResponse struct {
	Users []TailscaleUser `json:"users"`
}

// The scopes required for the tailscale provider
func TailscaleScopes() []string {
	return []string{"users:read"}
}

// The tailscale endpoint
var TailscaleEndpoint = oauth2.Endpoint{
	TokenURL: "https://api.tailscale.com/api/v2/oauth/token",
}

func GetTailscaleEmail(client *http.Client) (string, error) {
	// Get the user info from tailscale using the oauth http client
	res, err := client.Get("https://api.tailscale.com/api/v2/tailnet/-/users")

	// Check if there was an error
	if err != nil {
		return "", err
	}

	log.Debug().Msg("Got response from tailscale")

	// Read the body of the response
	body, err := io.ReadAll(res.Body)

	// Check if there was an error
	if err != nil {
		return "", err
	}

	log.Debug().Msg("Read body from tailscale")

	// Parse the body into a user struct
	var users TailscaleUserInfoResponse

	// Unmarshal the body into the user struct
	err = json.Unmarshal(body, &users)

	// Check if there was an error
	if err != nil {
		return "", err
	}

	log.Debug().Msg("Parsed users from tailscale")

	// Return the email of the first user
	return users.Users[0].LoginName, nil
}
