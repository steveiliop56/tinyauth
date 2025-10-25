package decoders_test

import (
	"testing"
	"tinyauth/internal/config"
	"tinyauth/internal/utils/decoders"

	"gotest.tools/v3/assert"
)

func TestDecodeEnv(t *testing.T) {
	// Setup
	env := map[string]string{
		"PROVIDERS_GOOGLE_CLIENT_ID":        "google-client-id",
		"PROVIDERS_GOOGLE_CLIENT_SECRET":    "google-client-secret",
		"PROVIDERS_MY_GITHUB_CLIENT_ID":     "github-client-id",
		"PROVIDERS_MY_GITHUB_CLIENT_SECRET": "github-client-secret",
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
	result, err := decoders.DecodeEnv[config.Providers, config.OAuthServiceConfig](env, "providers")
	assert.NilError(t, err)
	assert.DeepEqual(t, result, expected)
}
