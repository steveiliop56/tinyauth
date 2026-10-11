package service

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"golang.org/x/oauth2"
)

func TestOAuthService_UserMapping(t *testing.T) {
	tests := []struct {
		name             string
		userMapping      []string
		extractedClaims  model.Claims
		expectedUsername string
	}{
		{
			name: "Map user email to custom username",
			userMapping: []string{
				"user@example.com:customuser",
			},
			extractedClaims: model.Claims{
				Email:             "user@example.com",
				PreferredUsername: "",
			},
			expectedUsername: "customuser",
		},
		{
			name: "Case insensitive email matching",
			userMapping: []string{
				"Alice@example.com:alice",
			},
			extractedClaims: model.Claims{
				Email:             "alice@EXAMPLE.COM",
				PreferredUsername: "",
			},
			expectedUsername: "alice",
		},
		{
			name: "Override existing preferred username if mapped",
			userMapping: []string{
				"bob@example.com:robert",
			},
			extractedClaims: model.Claims{
				Email:             "bob@example.com",
				PreferredUsername: "bob_github",
			},
			expectedUsername: "robert",
		},
		{
			name: "Keep original preferred username when not in mapping",
			userMapping: []string{
				"other@example.com:other",
			},
			extractedClaims: model.Claims{
				Email:             "unmapped@example.com",
				PreferredUsername: "unmapped_login",
			},
			expectedUsername: "unmapped_login",
		},
		{
			name:        "Leave preferred username empty when unmapped and absent",
			userMapping: []string{},
			extractedClaims: model.Claims{
				Email:             "unmapped@example.com",
				PreferredUsername: "",
			},
			expectedUsername: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := model.OAuthServiceConfig{
				UserMapping: tt.userMapping,
			}
			svc := NewOAuthService(cfg, "test", context.Background())
			svc.WithUserinfoExtractor(func(client *http.Client, ctx context.Context, url string, mapClaims MapClaims) (*model.Claims, error) {
				claims := tt.extractedClaims
				return &claims, nil
			})

			// Dummy token
			token := &oauth2.Token{
				AccessToken: "dummy-token",
			}
			claims, err := svc.GetUserinfo(token)
			assert.NoError(t, err)
			assert.NotNil(t, claims)
			assert.Equal(t, tt.expectedUsername, claims.PreferredUsername)
		})
	}
}
