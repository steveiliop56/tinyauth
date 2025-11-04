package decoders_test

import (
	"testing"
	"tinyauth/internal/config"
	"tinyauth/internal/utils/decoders"

	"gotest.tools/v3/assert"
)

func TestDecodeFlags(t *testing.T) {
	// Setup
	args := []string{
		"--providers-google-clientid=google-client-id",
		"--providers-google-clientsecret=google-client-secret",
		"--providers-github-clientid=github-client-id",
		"--providers-github-clientsecret=github-client-secret",
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
	result, err := decoders.DecodeFlags[config.Providers](args)
	assert.NilError(t, err)
	assert.DeepEqual(t, result, expected)
}
