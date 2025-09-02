package decoders_test

import (
	"reflect"
	"testing"
	"tinyauth/internal/config"
	"tinyauth/internal/utils/decoders"
)

func TestDecodeHeaders(t *testing.T) {
	// Variables
	expected := config.App{
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
	}
	test := map[string]string{
		"Tinyauth-Config-Domain":                   "example.com",
		"Tinyauth-Users-Allow":                     "user1,user2",
		"Tinyauth-Users-Block":                     "user3",
		"Tinyauth-OAuth-Whitelist":                 "somebody@example.com",
		"Tinyauth-OAuth-Groups":                    "group3",
		"Tinyauth-IP-Allow":                        "10.71.0.1/24,10.71.0.2",
		"Tinyauth-IP-Block":                        "10.10.10.10,10.0.0.0/24",
		"Tinyauth-IP-Bypass":                       "192.168.1.1",
		"Tinyauth-Response-Headers":                "X-Foo=Bar,X-Baz=Qux",
		"Tinyauth-Response-BasicAuth-Username":     "admin",
		"Tinyauth-Response-BasicAuth-Password":     "password",
		"Tinyauth-Response-BasicAuth-PasswordFile": "/path/to/passwordfile",
		"Tinyauth-Path-Allow":                      "/public",
		"Tinyauth-Path-Block":                      "/private",
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
