package decoders

import (
	"tinyauth/internal/config"

	"github.com/traefik/paerser/parser"
)

func DecodeLabels(labels map[string]string) (config.Apps, error) {
	var appLabels config.Apps

	err := parser.Decode(labels, &appLabels, "tinyauth", "tinyauth.apps")

	if err != nil {
		return config.Apps{}, err
	}

	return appLabels, nil
}
