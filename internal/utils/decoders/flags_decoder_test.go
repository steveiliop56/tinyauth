package decoders_test

import (
	"testing"
	"tinyauth/internal/config"
	"tinyauth/internal/utils/decoders"

	"gotest.tools/v3/assert"
)

func TestDecodeFlags(t *testing.T) {
	// Setup
	flags := map[string]string{
		"--providers-google-client-id":        "google-client-id",
		"--providers-google-client-secret":    "google-client-secret",
		"--providers-my-github-client-id":     "github-client-id",
		"--providers-my-github-client-secret": "github-client-secret",
	}

	expected := config.Providers{
		Providers: map[string]config.OAuthServiceConfig{
			"google": {
				ClientID:     "google-client-id",
				ClientSecret: "google-client-secret",
			},
			"myGithub": {
				ClientID:     "github-client-id",
				ClientSecret: "github-client-secret",
			},
		},
	}

	// Execute
	result, err := decoders.DecodeFlags[config.Providers, config.OAuthServiceConfig](flags, "providers")
	assert.NilError(t, err)
	assert.DeepEqual(t, result, expected)
}
