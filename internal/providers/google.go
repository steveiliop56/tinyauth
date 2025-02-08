package providers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

// Google works the same as the generic provider
type GoogleUserInfoResponse struct {
	Email string `json:"email"`
}

// The scopes required for the google provider
func GoogleScopes() []string {
	return []string{"https://www.googleapis.com/auth/userinfo.email"}
}

func GetGoogleEmail(client *http.Client) (string, error) {
	// Get the user info from google using the oauth http client
	res, resErr := client.Get("https://www.googleapis.com/userinfo/v2/me")

	// Check if there was an error
	if resErr != nil {
		return "", resErr
	}

	log.Debug().Msg("Got response from google")

	// Read the body of the response
	body, bodyErr := io.ReadAll(res.Body)

	// Check if there was an error
	if bodyErr != nil {
		return "", bodyErr
	}

	log.Debug().Msg("Read body from google")

	// Parse the body into a user struct
	var user GoogleUserInfoResponse

	// Unmarshal the body into the user struct
	jsonErr := json.Unmarshal(body, &user)

	// Check if there was an error
	if jsonErr != nil {
		return "", jsonErr
	}

	log.Debug().Msg("Parsed user from google")

	// Return the email
	return user.Email, nil
}
