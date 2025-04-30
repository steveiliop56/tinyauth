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
	// Create user struct
	var user constants.Claims

	// Get the user info from github using the oauth http client
	res, err := client.Get("https://api.github.com/user")

	// Check if there was an error
	if err != nil {
		return user, err
	}

	defer res.Body.Close()

	log.Debug().Msg("Got user response from github")

	// Read the body of the response
	body, err := io.ReadAll(res.Body)

	// Check if there was an error
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Read user body from github")

	// Parse the body into a user struct
	var userInfo GithubUserInfoResponse

	// Unmarshal the body into the user struct
	err = json.Unmarshal(body, &userInfo)

	// Check if there was an error
	if err != nil {
		return user, err
	}

	// Get the user emails from github using the oauth http client
	res, err = client.Get("https://api.github.com/user/emails")

	// Check if there was an error
	if err != nil {
		return user, err
	}

	defer res.Body.Close()

	log.Debug().Msg("Got email response from github")

	// Read the body of the response
	body, err = io.ReadAll(res.Body)

	// Check if there was an error
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Read email body from github")

	// Parse the body into a user struct
	var emails GithubEmailResponse

	// Unmarshal the body into the user struct
	err = json.Unmarshal(body, &emails)

	// Check if there was an error
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Parsed emails from github")

	// Find and return the primary email
	for _, email := range emails {
		if email.Primary {
			// Set the email then exit
			user.Email = email.Email
			break
		}
	}

	// If no primary email was found, use the first available email
	if len(emails) == 0 {
		return user, errors.New("no emails found")
	}

	// Set the email if it is not set picking the first one
	if user.Email == "" {
		user.Email = emails[0].Email
	}

	// Set the username and name
	user.PreferredUsername = userInfo.Login
	user.Name = userInfo.Name

	// Return
	return user, nil
}
