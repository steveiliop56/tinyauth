package decoders_test

import (
	"testing"
	"tinyauth/internal/config"
	"tinyauth/internal/utils/decoders"

	"gotest.tools/v3/assert"
)

func TestDecodeEnv(t *testing.T) {
	// Setup
	env := []string{
		"TINYAUTH_PROVIDERS_GOOGLE_CLIENTID=google-client-id",
		"TINYAUTH_PROVIDERS_GOOGLE_CLIENTSECRET=google-client-secret",
		"TINYAUTH_PROVIDERS_GITHUB_CLIENTID=github-client-id",
		"TINYAUTH_PROVIDERS_GITHUB_CLIENTSECRET=github-client-secret",
	}

	expected := config.Providers{
		Providers: map[string]config.OAuthServiceConfig{
			"google": {
				ClientID:     "google-client-id",
				ClientSecret: "google-client-secret",
			},
			"github": {
				ClientID:     "github-client-id",
				ClientSecret: "github-client-secret",
			},
		},
	}

	// Execute
	result, err := decoders.DecodeEnv[config.Providers](env)
	assert.NilError(t, err)
	assert.DeepEqual(t, result, expected)
}
