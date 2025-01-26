package providers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

type GenericUserInfoResponse struct {
	Email string `json:"email"`
}

func GetGenericEmail(client *http.Client, url string) (string, error) {
	res, resErr := client.Get(url)

	if resErr != nil {
		return "", resErr
	}

	log.Debug().Msg("Got response from generic provider")

	body, bodyErr := io.ReadAll(res.Body)

	if bodyErr != nil {
		return "", bodyErr
	}

	log.Debug().Msg("Read body from generic provider")

	var user GenericUserInfoResponse

	jsonErr := json.Unmarshal(body, &user)

	if jsonErr != nil {
		return "", jsonErr
	}

	log.Debug().Interface("user", user).Msg("Parsed user from generic provider")

	return user.Email, nil
}
