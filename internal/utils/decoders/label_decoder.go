package decoders

import (
	"github.com/tinyauthapp/paerser/parser"
)

func DecodeLabels[T any](labels map[string]string, root string) (T, error) {
	var labelsDecoded T

	err := parser.Decode(labels, &labelsDecoded, "tinyauth", "tinyauth."+root)

	if err != nil {
		return labelsDecoded, err
	}

	return labelsDecoded, nil
}
