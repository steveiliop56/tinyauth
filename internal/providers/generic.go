package providers

import (
	"encoding/json"
	"io"
	"net/http"
)

type GenericUserInfoResponse struct {
	Email string `json:"email"`
}

func GetGenericEmail(client *http.Client, url string) (string, error) {
	res, resErr := client.Get(url)

	if resErr != nil {
		return "", resErr
	}

	body, bodyErr := io.ReadAll(res.Body)

	if bodyErr != nil {
		return "", bodyErr
	}

	var user GenericUserInfoResponse

	jsonErr := json.Unmarshal(body, &user)

	if jsonErr != nil {
		return "", jsonErr
	}

	return user.Email, nil
}
