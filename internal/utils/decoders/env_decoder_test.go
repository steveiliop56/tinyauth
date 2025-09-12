package decoders_test

import (
	"testing"
	"tinyauth/internal/config"
	"tinyauth/internal/utils/decoders"

	"gotest.tools/v3/assert"
)

func TestDecodeEnv(t *testing.T) {
	// Variables
	expected := config.Providers{
		Providers: map[string]config.OAuthServiceConfig{
			"client1": {
				ClientID:           "client1-id",
				ClientSecret:       "client1-secret",
				Scopes:             []string{"client1-scope1", "client1-scope2"},
				RedirectURL:        "client1-redirect-url",
				AuthURL:            "client1-auth-url",
				UserinfoURL:        "client1-user-info-url",
				Name:               "Client1",
				InsecureSkipVerify: false,
			},
			"client2": {
				ClientID:           "client2-id",
				ClientSecret:       "client2-secret",
				Scopes:             []string{"client2-scope1", "client2-scope2"},
				RedirectURL:        "client2-redirect-url",
				AuthURL:            "client2-auth-url",
				UserinfoURL:        "client2-user-info-url",
				Name:               "My Awesome Client2",
				InsecureSkipVerify: false,
			},
		},
	}
	test := map[string]string{
		"PROVIDERS_CLIENT1_CLIENT_ID":            "client1-id",
		"PROVIDERS_CLIENT1_CLIENT_SECRET":        "client1-secret",
		"PROVIDERS_CLIENT1_SCOPES":               "client1-scope1,client1-scope2",
		"PROVIDERS_CLIENT1_REDIRECT_URL":         "client1-redirect-url",
		"PROVIDERS_CLIENT1_AUTH_URL":             "client1-auth-url",
		"PROVIDERS_CLIENT1_USER_INFO_URL":        "client1-user-info-url",
		"PROVIDERS_CLIENT1_NAME":                 "Client1",
		"PROVIDERS_CLIENT1_INSECURE_SKIP_VERIFY": "false",
		"PROVIDERS_CLIENT2_CLIENT_ID":            "client2-id",
		"PROVIDERS_CLIENT2_CLIENT_SECRET":        "client2-secret",
		"PROVIDERS_CLIENT2_SCOPES":               "client2-scope1,client2-scope2",
		"PROVIDERS_CLIENT2_REDIRECT_URL":         "client2-redirect-url",
		"PROVIDERS_CLIENT2_AUTH_URL":             "client2-auth-url",
		"PROVIDERS_CLIENT2_USER_INFO_URL":        "client2-user-info-url",
		"PROVIDERS_CLIENT2_NAME":                 "My Awesome Client2",
		"PROVIDERS_CLIENT2_INSECURE_SKIP_VERIFY": "false",
	}

	// Test
	res, err := decoders.DecodeEnv(test)
	assert.NilError(t, err)
	assert.DeepEqual(t, expected, res)
}
