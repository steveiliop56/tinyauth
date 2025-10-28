package decoders_test

import (
	"testing"
	"tinyauth/internal/config"
	"tinyauth/internal/utils/decoders"

	"gotest.tools/v3/assert"
)

func TestDecodeACLEnv(t *testing.T) {
	env := map[string]string{
		"TINYAUTH_APPS_MY_COOL_APP_CONFIG_DOMAIN":   "example.com",
		"TINYAUTH_APPS_MY_COOL_APP_USERS_ALLOW":     "user1,user2",
		"TINYAUTH_APPS_MY_COOL_APP_USERS_BLOCK":     "user3",
		"TINYAUTH_APPS_MY_COOL_APP_OAUTH_WHITELIST": "provider1",
		"TINYAUTH_APPS_MY_COOL_APP_OAUTH_GROUPS":    "group1,group2",
		"TINYAUTH_APPS_OTHERAPP_CONFIG_DOMAIN":      "test.com",
		"TINYAUTH_APPS_OTHERAPP_USERS_ALLOW":        "admin",
	}

	expected := config.Apps{
		Apps: map[string]config.App{
			"my_cool_app": {
				Config: config.AppConfig{
					Domain: "example.com",
				},
				Users: config.AppUsers{
					Allow: "user1,user2",
					Block: "user3",
				},
				OAuth: config.AppOAuth{
					Whitelist: "provider1",
					Groups:    "group1,group2",
				},
			},
			"otherapp": {
				Config: config.AppConfig{
					Domain: "test.com",
				},
				Users: config.AppUsers{
					Allow: "admin",
				},
			},
		},
	}

	// Execute
	result, err := decoders.DecodeACLEnv[config.Apps](env, "apps")
	assert.NilError(t, err)
	assert.DeepEqual(t, result, expected)
}

func TestDecodeACLFlags(t *testing.T) {
	// Setup
	flags := map[string]string{
		"tinyauth-apps-webapp-config-domain":   "webapp.example.com",
		"tinyauth-apps-webapp-users-allow":     "alice,bob",
		"tinyauth-apps-webapp-oauth-whitelist": "google",
		"tinyauth-apps-api-config-domain":      "api.example.com",
		"tinyauth-apps-api-users-block":        "banned",
	}

	expected := config.Apps{
		Apps: map[string]config.App{
			"webapp": {
				Config: config.AppConfig{
					Domain: "webapp.example.com",
				},
				Users: config.AppUsers{
					Allow: "alice,bob",
				},
				OAuth: config.AppOAuth{
					Whitelist: "google",
				},
			},
			"api": {
				Config: config.AppConfig{
					Domain: "api.example.com",
				},
				Users: config.AppUsers{
					Block: "banned",
				},
			},
		},
	}

	// Execute
	result, err := decoders.DecodeACLFlags[config.Apps](flags, "apps")
	assert.NilError(t, err)
	assert.DeepEqual(t, result, expected)
}
