package decoders

import (
	"strings"

	"github.com/traefik/paerser/parser"
)

func DecodeFlags[T any, C any](flags map[string]string, subName string) (T, error) {
	var result T

	filtered := filterFlags(flags)
	normalized := normalizeKeys[C](filtered, subName, "_")

	err := parser.Decode(normalized, &result, "tinyauth", "tinyauth."+subName)

	if err != nil {
		return result, err
	}

	return result, nil
}

func DecodeACLFlags[T any](flags map[string]string, subName string) (T, error) {
	var result T

	filtered := filterFlags(flags)
	normalized := normalizeACLKeys[T](filtered, subName, "-")

	err := parser.Decode(normalized, &result, "tinyauth", "tinyauth."+subName)

	if err != nil {
		return result, err
	}

	return result, nil
}

func filterFlags(flags map[string]string) map[string]string {
	filtered := make(map[string]string)
	for k, v := range flags {
		filtered[strings.TrimPrefix(k, "--")] = v
	}
	return filtered
}
