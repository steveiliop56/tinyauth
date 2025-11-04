package decoders

import (
	"github.com/traefik/paerser/parser"
)

func DecodeLabels[T any](labels map[string]string) (T, error) {
	var target T

	err := parser.Decode(labels, &target, "tinyauth")

	if err != nil {
		return target, err
	}

	return target, nil
}
