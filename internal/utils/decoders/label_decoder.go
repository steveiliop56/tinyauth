package decoders

import (
	"tinyauth/internal/config"

	"github.com/traefik/paerser/parser"
)

func DecodeLabels(labels map[string]string) (config.AppConfigs, error) {
	var appLabels config.AppConfigs

	err := parser.Decode(labels, &appLabels, "tinyauth", "tinyauth.apps")

	if err != nil {
		return config.AppConfigs{}, err
	}

	return appLabels, nil
}
