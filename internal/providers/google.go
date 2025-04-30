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
	// Create user struct
	var user constants.Claims

	// Get the user info from google using the oauth http client
	res, err := client.Get("https://www.googleapis.com/userinfo/v2/me")

	// Check if there was an error
	if err != nil {
		return user, err
	}

	defer res.Body.Close()

	log.Debug().Msg("Got response from google")

	// Read the body of the response
	body, err := io.ReadAll(res.Body)

	// Check if there was an error
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Read body from google")

	// Create a new user info struct
	var userInfo GoogleUserInfoResponse

	// Unmarshal the body into the user struct
	err = json.Unmarshal(body, &userInfo)

	// Check if there was an error
	if err != nil {
		return user, err
	}

	log.Debug().Msg("Parsed user from google")

	// Map the user info to the user struct
	user.PreferredUsername = strings.Split(userInfo.Email, "@")[0]
	user.Name = userInfo.Name
	user.Email = userInfo.Email

	// Return the user
	return user, nil
}
