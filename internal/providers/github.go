package providers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
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

	body, bodyErr := io.ReadAll(res.Body)

	if bodyErr != nil {
		return "", bodyErr
	}

	var emails GithubUserInfoResponse

	jsonErr := json.Unmarshal(body, &emails)

	if jsonErr != nil {
		return "", jsonErr
	}

	for _, email := range emails {
		if email.Primary {
			return email.Email, nil
		}
	}

	return "", errors.New("no primary email found")
}
