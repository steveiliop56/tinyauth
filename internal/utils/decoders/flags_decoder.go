package decoders

import (
	"strings"
	"tinyauth/internal/config"
	"tinyauth/internal/utils"

	"github.com/traefik/paerser/parser"
)

func DecodeFlags(flags map[string]string) (config.Providers, error) {
	// Normalize flags (sorry to whoever has to read this)
	// --providers-client1-client-id -> tinyauth.providers.client1.clientId
	normalized := make(map[string]string)
	for k, v := range flags {
		newKey := ""

		nk := strings.TrimPrefix(k, "--")
		parts := strings.SplitN(nk, "-", 4)

		for i, part := range parts {
			if i == 3 {
				subParts := strings.Split(part, "-")
				for j, subPart := range subParts {
					if j == 0 {
						newKey += "." + subPart
					} else {
						newKey += utils.Capitalize(subPart)
					}
				}
				continue
			}
			if i == 0 {
				newKey += part
				continue
			}
			newKey += "." + part
		}

		newKey = "tinyauth." + newKey
		normalized[newKey] = v

	}

	// Decode
	var providers config.Providers

	err := parser.Decode(normalized, &providers, "tinyauth", "tinyauth.providers")

	if err != nil {
		return config.Providers{}, err
	}

	return providers, nil
}
