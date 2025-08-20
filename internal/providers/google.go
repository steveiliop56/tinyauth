package providers

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"tinyauth/internal/constants"

	"github.com/rs/zerolog/log"
)

// Response for the google user endpoint
type GoogleUserInfoResponse struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// The scopes required for the google provider
func GoogleScopes() []string {
	return []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"}
}

func GetGoogleUser(client *http.Client) (constants.Claims, error) {
	var user constants.Claims

	res, err := client.Get("https://www.googleapis.com/userinfo/v2/me")
	if err != nil {
		return user, err
	}
	defer res.Body.Close()

	log.Debug().Msg("Got response from google")

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Read body from google")

	var userInfo GoogleUserInfoResponse

	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Parsed user from google")

	user.PreferredUsername = strings.Split(userInfo.Email, "@")[0]
	user.Name = userInfo.Name
	user.Email = userInfo.Email

	return user, nil
}
