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
	res, err := client.Get(url)

	// Check if there was an error
	if err != nil {
		return "", err
	}

	log.Debug().Msg("Got response from generic provider")

	// Read the body of the response
	body, err := io.ReadAll(res.Body)

	// Check if there was an error
	if err != nil {
		return "", err
	}

	log.Debug().Msg("Read body from generic provider")

	// Parse the body into a user struct
	var user GenericUserInfoResponse

	// Unmarshal the body into the user struct
	err = json.Unmarshal(body, &user)

	// Check if there was an error
	if err != nil {
		return "", err
	}

	log.Debug().Msg("Parsed user from generic provider")

	// Return the email
	return user.Email, nil
}
