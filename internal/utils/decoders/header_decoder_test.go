package decoders_test

import (
	"reflect"
	"testing"
	"tinyauth/internal/config"
	"tinyauth/internal/utils/decoders"
)

func TestDecodeHeaders(t *testing.T) {
	// Variables
	expected := config.AppConfigs{
		Apps: map[string]config.App{
			"foo": {
				Config: config.AppConfig{
					Domain: "example.com",
				},
				Users: config.AppUsers{
					Allow: "user1,user2",
					Block: "user3",
				},
				OAuth: config.AppOAuth{
					Whitelist: "somebody@example.com",
					Groups:    "group3",
				},
				IP: config.AppIP{
					Allow:  []string{"10.71.0.1/24", "10.71.0.2"},
					Block:  []string{"10.10.10.10", "10.0.0.0/24"},
					Bypass: []string{"192.168.1.1"},
				},
				Response: config.AppResponse{
					Headers: []string{"X-Foo=Bar", "X-Baz=Qux"},
					BasicAuth: config.AppBasicAuth{
						Username:     "admin",
						Password:     "password",
						PasswordFile: "/path/to/passwordfile",
					},
				},
				Path: config.AppPath{
					Allow: "/public",
					Block: "/private",
				},
			},
		},
	}
	test := map[string]string{
		"Tinyauth-Apps-Foo-Config-Domain":                   "example.com",
		"Tinyauth-Apps-Foo-Users-Allow":                     "user1,user2",
		"Tinyauth-Apps-Foo-Users-Block":                     "user3",
		"Tinyauth-Apps-Foo-OAuth-Whitelist":                 "somebody@example.com",
		"Tinyauth-Apps-Foo-OAuth-Groups":                    "group3",
		"Tinyauth-Apps-Foo-IP-Allow":                        "10.71.0.1/24,10.71.0.2",
		"Tinyauth-Apps-Foo-IP-Block":                        "10.10.10.10,10.0.0.0/24",
		"Tinyauth-Apps-Foo-IP-Bypass":                       "192.168.1.1",
		"Tinyauth-Apps-Foo-Response-Headers":                "X-Foo=Bar,X-Baz=Qux",
		"Tinyauth-Apps-Foo-Response-BasicAuth-Username":     "admin",
		"Tinyauth-Apps-Foo-Response-BasicAuth-Password":     "password",
		"Tinyauth-Apps-Foo-Response-BasicAuth-PasswordFile": "/path/to/passwordfile",
		"Tinyauth-Apps-Foo-Path-Allow":                      "/public",
		"Tinyauth-Apps-Foo-Path-Block":                      "/private",
	}

	// Test
	result, err := decoders.DecodeHeaders(test)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !reflect.DeepEqual(expected, result) {
		t.Fatalf("Expected %v but got %v", expected, result)
	}
}
