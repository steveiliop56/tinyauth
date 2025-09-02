package decoders

import (
	"tinyauth/internal/config"

	"github.com/traefik/paerser/parser"
)

func DecodeLabels(labels map[string]string) (config.Labels, error) {
	var appLabels config.Labels

	err := parser.Decode(labels, &appLabels, "tinyauth")

	if err != nil {
		return config.Labels{}, err
	}

	return appLabels, nil
}
