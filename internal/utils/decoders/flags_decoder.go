package decoders

import (
	"strings"

	"github.com/traefik/paerser/flag"
)

func DecodeFlags[T any](args []string) (T, error) {
	var target T
	var formatted = []string{}

	for _, arg := range args {
		argFmt := strings.TrimPrefix(arg, "--")
		argParts := strings.SplitN(argFmt, "=", 2)

		if len(argParts) != 2 {
			continue
		}

		key := argParts[0]
		value := argParts[1]

		formatted = append(formatted, "--"+strings.ReplaceAll(key, "-", ".")+"="+value)
	}

	err := flag.Decode(formatted, &target)

	if err != nil {
		return target, err
	}

	return target, nil
}
