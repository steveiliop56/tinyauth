package providers

import (
	"encoding/json"
	"io"
	"net/http"
	"tinyauth/internal/constants"

	"github.com/rs/zerolog/log"
)

func GetGenericUser(client *http.Client, url string) (constants.Claims, error) {
	// Create user struct
	var user constants.Claims

	// Using the oauth client get the user info url
	res, err := client.Get(url)

	// Check if there was an error
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Got response from generic provider")

	// Read the body of the response
	body, err := io.ReadAll(res.Body)

	// Check if there was an error
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Read body from generic provider")

	// Unmarshal the body into the user struct
	err = json.Unmarshal(body, &user)

	// Check if there was an error
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Parsed user from generic provider")

	// Return the user
	return user, nil
}
