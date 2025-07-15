package providers

import (
	"encoding/json"
	"io"
	"net/http"
	"tinyauth/internal/constants"

	"github.com/rs/zerolog/log"
)

func GetGenericUser(client *http.Client, url string) (constants.Claims, error) {
	var user constants.Claims

	res, err := client.Get(url)
	if err != nil {
		return user, err
	}
	defer res.Body.Close()

	log.Debug().Msg("Got response from generic provider")

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Read body from generic provider")

	err = json.Unmarshal(body, &user)
	if err != nil {
		return user, err
	}

	log.Debug().Interface("user", user).Msg("Parsed user from generic provider")
	return user, nil
}
