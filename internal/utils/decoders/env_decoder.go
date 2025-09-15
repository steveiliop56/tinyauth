package decoders

import (
	"tinyauth/internal/config"

	"github.com/traefik/paerser/parser"
)

func DecodeEnv(env map[string]string) (config.Providers, error) {
	normalized := NormalizeKeys(env, "tinyauth", "_")
	var providers config.Providers

	err := parser.Decode(normalized, &providers, "tinyauth", "tinyauth.providers")

	if err != nil {
		return config.Providers{}, err
	}

	return providers, nil
}
