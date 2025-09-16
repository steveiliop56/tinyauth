package decoders

import (
	"strings"
	"tinyauth/internal/config"

	"github.com/traefik/paerser/parser"
)

func DecodeFlags(flags map[string]string) (config.Providers, error) {
	filtered := filterFlags(flags)
	normalized := NormalizeKeys(filtered, "tinyauth", "-")
	var providers config.Providers

	err := parser.Decode(normalized, &providers, "tinyauth", "tinyauth.providers")

	if err != nil {
		return config.Providers{}, err
	}

	return providers, nil
}

func filterFlags(flags map[string]string) map[string]string {
	filtered := make(map[string]string)
	for k, v := range flags {
		filtered[strings.TrimPrefix(k, "--")] = v
	}
	return filtered
}
