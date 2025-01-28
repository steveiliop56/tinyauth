package providers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

type GoogleUserInfoResponse struct {
	Email string `json:"email"`
}

func GoogleScopes() []string {
	return []string{"https://www.googleapis.com/auth/userinfo.email"}
}

func GetGoogleEmail(client *http.Client) (string, error) {
	res, resErr := client.Get("https://www.googleapis.com/userinfo/v2/me")

	if resErr != nil {
		return "", resErr
	}

	log.Debug().Msg("Got response from google")

	body, bodyErr := io.ReadAll(res.Body)

	if bodyErr != nil {
		return "", bodyErr
	}

	log.Debug().Msg("Read body from google")

	var user GoogleUserInfoResponse

	jsonErr := json.Unmarshal(body, &user)

	if jsonErr != nil {
		return "", jsonErr
	}

	log.Debug().Msg("Parsed user from google")

	return user.Email, nil
}
