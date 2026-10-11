package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseUserMapping(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected map[string]string
	}{
		{
			name:     "Empty list",
			input:    []string{},
			expected: map[string]string{},
		},
		{
			name: "Colon separated mappings with whitespace and case normalization",
			input: []string{
				"  Alice@example.com:alice  ",
				"bob@example.com:robert",
			},
			expected: map[string]string{
				"alice@example.com": "alice",
				"bob@example.com":   "robert",
			},
		},
		{
			name: "Equal separated mappings and comments",
			input: []string{
				"# this is a comment",
				"",
				"carol@example.com=carol",
				"   ",
				"dave@example.com:david",
			},
			expected: map[string]string{
				"carol@example.com": "carol",
				"dave@example.com":  "david",
			},
		},
		{
			name: "Later entries override earlier entries",
			input: []string{
				"user@example.com:first",
				"user@example.com:second",
			},
			expected: map[string]string{
				"user@example.com": "second",
			},
		},
		{
			name: "Ignore entries without separator or missing parts",
			input: []string{
				"invalid-entry",
				":empty-email",
				"empty-username:",
				"valid@example.com:user",
			},
			expected: map[string]string{
				"valid@example.com": "user",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseUserMapping(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
