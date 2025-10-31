package decoders

import (
	"github.com/traefik/paerser/parser"
)

func DecodeEnv[T any, C any](env map[string]string, subName string) (T, error) {
	var result T

	normalized := normalizeKeys[C](env, subName, "_")

	err := parser.Decode(normalized, &result, "tinyauth", "tinyauth."+subName)

	if err != nil {
		return result, err
	}

	return result, nil
}

func DecodeACLEnv[T any](env map[string]string, subName string) (T, error) {
	var result T

	normalized := normalizeACLKeys[T](env, subName, "_")

	err := parser.Decode(normalized, &result, "tinyauth", "tinyauth."+subName)

	if err != nil {
		return result, err
	}

	return result, nil
}
