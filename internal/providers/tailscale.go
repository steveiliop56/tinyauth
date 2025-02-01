package providers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

type TailscaleUser struct {
	LoginName string `json:"loginName"`
}

type TailscaleUserInfoResponse struct {
	Users []TailscaleUser `json:"users"`
}

func TailscaleScopes() []string {
	return []string{"users:read"}
}

var TailscaleEndpoint = oauth2.Endpoint{
	TokenURL: "https://api.tailscale.com/api/v2/oauth/token",
}

func GetTailscaleEmail(client *http.Client) (string, error) {
	res, resErr := client.Get("https://api.tailscale.com/api/v2/tailnet/-/users")

	if resErr != nil {
		return "", resErr
	}

	log.Debug().Msg("Got response from tailscale")

	body, bodyErr := io.ReadAll(res.Body)

	if bodyErr != nil {
		return "", bodyErr
	}

	log.Debug().Msg("Read body from tailscale")

	var users TailscaleUserInfoResponse

	jsonErr := json.Unmarshal(body, &users)

	if jsonErr != nil {
		return "", jsonErr
	}

	log.Debug().Msg("Parsed users from tailscale")

	return users.Users[0].LoginName, nil
}
