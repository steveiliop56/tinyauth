package providers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"tinyauth/internal/constants"

	"github.com/rs/zerolog/log"
)

// Response for the github email endpoint
type GithubEmailResponse []struct {
	Email   string `json:"email"`
	Primary bool   `json:"primary"`
}

// Response for the github user endpoint
type GithubUserInfoResponse struct {
	Login string `json:"login"`
	Name  string `json:"name"`
}

// The scopes required for the github provider
func GithubScopes() []string {
	return []string{"user:email", "read:user"}
}

func GetGithubUser(client *http.Client) (constants.Claims, error) {
	var user constants.Claims

	res, err := client.Get("https://api.github.com/user")
	if err != nil {
		return user, err
	}
	defer res.Body.Close()

	log.Debug().Msg("Got user response from github")

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Read user body from github")

	var userInfo GithubUserInfoResponse

	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return user, err
	}

	res, err = client.Get("https://api.github.com/user/emails")
	if err != nil {
		return user, err
	}
	defer res.Body.Close()

	log.Debug().Msg("Got email response from github")

	body, err = io.ReadAll(res.Body)
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Read email body from github")

	var emails GithubEmailResponse

	err = json.Unmarshal(body, &emails)
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Parsed emails from github")

	// Find and return the primary email
	for _, email := range emails {
		if email.Primary {
			log.Debug().Str("email", email.Email).Msg("Found primary email")
			user.Email = email.Email
			break
		}
	}

	if len(emails) == 0 {
		return user, errors.New("no emails found")
	}

	// Use first available email if no primary email was found
	if user.Email == "" {
		log.Warn().Str("email", emails[0].Email).Msg("No primary email found, using first email")
		user.Email = emails[0].Email
	}

	user.PreferredUsername = userInfo.Login
	user.Name = userInfo.Name

	return user, nil
}
