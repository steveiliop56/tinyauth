package decoders_test

import (
	"testing"
	"tinyauth/internal/config"
	"tinyauth/internal/utils/decoders"

	"gotest.tools/v3/assert"
)

func TestDecodeFlags(t *testing.T) {
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
		"--providers-client1-client-id":            "client1-id",
		"--providers-client1-client-secret":        "client1-secret",
		"--providers-client1-scopes":               "client1-scope1,client1-scope2",
		"--providers-client1-redirect-url":         "client1-redirect-url",
		"--providers-client1-auth-url":             "client1-auth-url",
		"--providers-client1-user-info-url":        "client1-user-info-url",
		"--providers-client1-name":                 "Client1",
		"--providers-client1-insecure-skip-verify": "false",
		"--providers-client2-client-id":            "client2-id",
		"--providers-client2-client-secret":        "client2-secret",
		"--providers-client2-scopes":               "client2-scope1,client2-scope2",
		"--providers-client2-redirect-url":         "client2-redirect-url",
		"--providers-client2-auth-url":             "client2-auth-url",
		"--providers-client2-user-info-url":        "client2-user-info-url",
		"--providers-client2-name":                 "My Awesome Client2",
		"--providers-client2-insecure-skip-verify": "false",
	}

	// Test
	res, err := decoders.DecodeFlags(test)
	assert.NilError(t, err)
	assert.DeepEqual(t, expected, res)
}
