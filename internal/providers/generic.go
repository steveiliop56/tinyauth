package providers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

func GetGenericUser(client *http.Client, url string) (map[string]interface{}, error) {
	// Create user struct
	user := make(map[string]interface{})

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
