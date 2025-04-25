package providers

import (
	"encoding/json"
	"io"
	"net/http"
	"tinyauth/internal/constants"

	"github.com/rs/zerolog/log"
)

// The scopes required for the google provider
func GoogleScopes() []string {
	return []string{"https://www.googleapis.com/auth/userinfo.email"}
}

func GetGoogleUser(client *http.Client) (constants.Claims, error) {
	// Create user struct
	var user constants.Claims

	// Get the user info from google using the oauth http client
	res, err := client.Get("https://www.googleapis.com/userinfo/v2/me")

	// Check if there was an error
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Got response from google")

	// Read the body of the response
	body, err := io.ReadAll(res.Body)

	// Check if there was an error
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Read body from google")

	// Unmarshal the body into the user struct
	err = json.Unmarshal(body, &user)

	// Check if there was an error
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Parsed user from google")

	// Return the user
	return user, nil
}
