package decoders

import (
	"reflect"
	"strings"

	"github.com/stoewer/go-strcase"
)

func normalizeKeys[T any](input map[string]string, root string, sep string) map[string]string {
	knownKeys := getKnownKeys[T]()
	normalized := make(map[string]string)

	for k, v := range input {
		parts := []string{"tinyauth"}

		key := strings.ToLower(k)
		key = strings.ReplaceAll(key, sep, "-")

		if !strings.HasPrefix(key, root+"-") {
			continue
		}

		suffix := ""

		for _, known := range knownKeys {
			if strings.HasSuffix(key, known) {
				suffix = known
				break
			}
		}

		if suffix == "" {
			continue
		}

		parts = append(parts, root)

		id := strings.TrimPrefix(key, root+"-")
		id = strings.TrimSuffix(id, "-"+suffix)

		if id == "" {
			continue
		}

		parts = append(parts, id)
		parts = append(parts, suffix)

		final := ""

		for i, part := range parts {
			if i > 0 {
				final += "."
			}
			final += strcase.LowerCamelCase(part)
		}

		normalized[final] = v
	}

	return normalized
}

func getKnownKeys[T any]() []string {
	var keys []string
	var t T

	v := reflect.ValueOf(t)
	typeOfT := v.Type()

	for field := range typeOfT.NumField() {
		if typeOfT.Field(field).Tag.Get("field") != "" {
			keys = append(keys, typeOfT.Field(field).Tag.Get("field"))
			continue
		}
		keys = append(keys, strcase.KebabCase(typeOfT.Field(field).Name))
	}

	return keys
}
