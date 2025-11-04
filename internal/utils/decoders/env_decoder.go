package decoders

import (
	"github.com/traefik/paerser/env"
)

func DecodeEnv[T any](environ []string) (T, error) {
	var target T

	err := env.Decode(environ, "TINYAUTH_", &target)

	if err != nil {
		return target, err
	}

	return target, nil
}
