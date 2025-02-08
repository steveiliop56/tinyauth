package providers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

// We are assuming that the generic provider will return a JSON object with an email field
type GenericUserInfoResponse struct {
	Email string `json:"email"`
}

func GetGenericEmail(client *http.Client, url string) (string, error) {
	// Using the oauth client get the user info url
	res, resErr := client.Get(url)

	// Check if there was an error
	if resErr != nil {
		return "", resErr
	}

	log.Debug().Msg("Got response from generic provider")

	// Read the body of the response
	body, bodyErr := io.ReadAll(res.Body)

	// Check if there was an error
	if bodyErr != nil {
		return "", bodyErr
	}

	log.Debug().Msg("Read body from generic provider")

	// Parse the body into a user struct
	var user GenericUserInfoResponse

	// Unmarshal the body into the user struct
	jsonErr := json.Unmarshal(body, &user)

	// Check if there was an error
	if jsonErr != nil {
		return "", jsonErr
	}

	log.Debug().Msg("Parsed user from generic provider")

	// Return the email
	return user.Email, nil
}
