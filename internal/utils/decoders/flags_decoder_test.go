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
		Providers: map[string]config.ProviderConfig{
			"client1": {
				Config: config.OAuthServiceConfig{
					ClientID:           "client1-id",
					ClientSecret:       "client1-secret",
					Scopes:             []string{"client1-scope1", "client1-scope2"},
					RedirectURL:        "client1-redirect-url",
					AuthURL:            "client1-auth-url",
					UserinfoURL:        "client1-user-info-url",
					InsecureSkipVerify: false,
				},
			},
			"client2": {
				Config: config.OAuthServiceConfig{
					ClientID:           "client2-id",
					ClientSecret:       "client2-secret",
					Scopes:             []string{"client2-scope1", "client2-scope2"},
					RedirectURL:        "client2-redirect-url",
					AuthURL:            "client2-auth-url",
					UserinfoURL:        "client2-user-info-url",
					InsecureSkipVerify: false,
				},
			},
		},
	}
	test := map[string]string{
		"--providers-client1-config-client-id":            "client1-id",
		"--providers-client1-config-client-secret":        "client1-secret",
		"--providers-client1-config-scopes":               "client1-scope1,client1-scope2",
		"--providers-client1-config-redirect-url":         "client1-redirect-url",
		"--providers-client1-config-auth-url":             "client1-auth-url",
		"--providers-client1-config-user-info-url":        "client1-user-info-url",
		"--providers-client1-config-insecure-skip-verify": "false",
		"--providers-client2-config-client-id":            "client2-id",
		"--providers-client2-config-client-secret":        "client2-secret",
		"--providers-client2-config-scopes":               "client2-scope1,client2-scope2",
		"--providers-client2-config-redirect-url":         "client2-redirect-url",
		"--providers-client2-config-auth-url":             "client2-auth-url",
		"--providers-client2-config-user-info-url":        "client2-user-info-url",
		"--providers-client2-config-insecure-skip-verify": "false",
	}

	// Test
	res, err := decoders.DecodeFlags(test)
	assert.NilError(t, err)
	assert.DeepEqual(t, expected, res)
}
