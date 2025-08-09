package providers

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"tinyauth/internal/constants"
	"github.com/rs/zerolog/log"
)

// Response for the Microsoft Graph user endpoint
type MicrosoftUserInfoResponse struct {
	Mail              string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"`
	DisplayName       string `json:"displayName"`
}

// The scopes required for the Microsoft provider
func MicrosoftScopes() []string {
	return []string{"openid", "profile", "email", "User.Read"}
}

func GetMicrosoftUser(client *http.Client, userURL ...string) (constants.Claims, error) {
	var user constants.Claims

	// Use custom user URL if provided, otherwise fall back to default
	url := "https://graph.microsoft.com/v1.0/me"
	if len(userURL) > 0 && userURL[0] != "" {
		url = userURL[0]
	}

	res, err := client.Get(url)
	if err != nil {
		return user, err
	}
	defer res.Body.Close()

	log.Debug().Msg("Got response from microsoft")

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Read body from microsoft")

	var userInfo MicrosoftUserInfoResponse

	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Parsed user from microsoft")

	// Prefer mail, fallback to UserPrincipalName
	email := userInfo.Mail
	if email == "" {
		email = userInfo.UserPrincipalName
	}
	user.PreferredUsername = strings.Split(email, "@")[0]
	user.Name = userInfo.DisplayName
	user.Email = email

	return user, nil
}
