package providers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

type GithubUserInfoResponse []struct {
	Email   string `json:"email"`
	Primary bool   `json:"primary"`
}

func GithubScopes() []string {
	return []string{"user:email"}
}

func GetGithubEmail(client *http.Client) (string, error) {
	res, resErr := client.Get("https://api.github.com/user/emails")

	if resErr != nil {
		return "", resErr
	}

	log.Debug().Msg("Got response from github")

	body, bodyErr := io.ReadAll(res.Body)

	if bodyErr != nil {
		return "", bodyErr
	}

	log.Debug().Msg("Read body from github")

	var emails GithubUserInfoResponse

	jsonErr := json.Unmarshal(body, &emails)

	if jsonErr != nil {
		return "", jsonErr
	}

	log.Debug().Interface("emails", emails).Msg("Parsed emails from github")

	for _, email := range emails {
		if email.Primary {
			return email.Email, nil
		}
	}

	return "", errors.New("no primary email found")
}
