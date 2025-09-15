package decoders_test

import (
	"testing"
	"tinyauth/internal/utils/decoders"

	"gotest.tools/v3/assert"
)

func TestNormalizeKeys(t *testing.T) {
	// Test with env
	test := map[string]string{
		"PROVIDERS_CLIENT1_CLIENT_ID":                    "my-client-id",
		"PROVIDERS_CLIENT1_CLIENT_SECRET":                "my-client-secret",
		"PROVIDERS_MY_AWESOME_CLIENT_CLIENT_ID":          "my-awesome-client-id",
		"PROVIDERS_MY_AWESOME_CLIENT_CLIENT_SECRET_FILE": "/path/to/secret",
	}
	expected := map[string]string{
		"tinyauth.providers.client1.clientId":                 "my-client-id",
		"tinyauth.providers.client1.clientSecret":             "my-client-secret",
		"tinyauth.providers.myAwesomeClient.clientId":         "my-awesome-client-id",
		"tinyauth.providers.myAwesomeClient.clientSecretFile": "/path/to/secret",
	}

	normalized := decoders.NormalizeKeys(test, "tinyauth", "_")
	assert.DeepEqual(t, normalized, expected)

	// Test with flags (assume -- is already stripped)
	test = map[string]string{
		"providers-client1-client-id":                    "my-client-id",
		"providers-client1-client-secret":                "my-client-secret",
		"providers-my-awesome-client-client-id":          "my-awesome-client-id",
		"providers-my-awesome-client-client-secret-file": "/path/to/secret",
	}
	expected = map[string]string{
		"tinyauth.providers.client1.clientId":                 "my-client-id",
		"tinyauth.providers.client1.clientSecret":             "my-client-secret",
		"tinyauth.providers.myAwesomeClient.clientId":         "my-awesome-client-id",
		"tinyauth.providers.myAwesomeClient.clientSecretFile": "/path/to/secret",
	}

	normalized = decoders.NormalizeKeys(test, "tinyauth", "-")
	assert.DeepEqual(t, normalized, expected)
}
