package decoders

import (
	"reflect"
	"strings"

	"github.com/stoewer/go-strcase"
)

func ParsePath(parts []string, idx int, t reflect.Type) []string {
	if idx >= len(parts) {
		return []string{}
	}

	if t.Kind() == reflect.Map {
		mapName := strings.ToLower(parts[idx])

		if idx+1 >= len(parts) {
			return []string{mapName}
		}

		elemType := t.Elem()
		keyEndIdx := idx + 1

		if elemType.Kind() == reflect.Struct {
			for i := idx + 1; i < len(parts); i++ {
				found := false

				for j := 0; j < elemType.NumField(); j++ {
					field := elemType.Field(j)
					if strings.EqualFold(parts[i], field.Name) {
						keyEndIdx = i
						found = true
						break
					}
				}

				if found {
					break
				}
			}
		}

		keyParts := parts[idx+1 : keyEndIdx]
		keyName := strings.ToLower(strings.Join(keyParts, "_"))

		rest := ParsePath(parts, keyEndIdx, elemType)
		return append([]string{mapName, keyName}, rest...)
	}

	if t.Kind() == reflect.Struct {
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if strings.EqualFold(parts[idx], field.Name) {
				rest := ParsePath(parts, idx+1, field.Type)
				return append([]string{strings.ToLower(field.Name)}, rest...)
			}
		}
	}

	return []string{}
}

func normalizeKeys[T any](input map[string]string, root string, sep string) map[string]string {
	knownKeys := getKnownKeys[T]()
	normalized := make(map[string]string)

	for k, v := range input {
		parts := []string{"tinyauth"}

		key := strings.ToLower(k)
		key = strings.ReplaceAll(key, sep, "-")

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

func normalizeACLKeys[T any](input map[string]string, root string, sep string) map[string]string {
	normalized := make(map[string]string)
	var t T
	rootType := reflect.TypeOf(t)

	for k, v := range input {
		parts := strings.Split(strings.ToLower(k), sep)

		if len(parts) < 2 {
			continue
		}

		if parts[0] != "tinyauth" {
			continue
		}

		if parts[1] != root {
			continue
		}

		if len(parts) > 2 {
			parsedParts := ParsePath(parts[2:], 0, rootType)

			if len(parsedParts) == 0 {
				continue
			}

			final := "tinyauth"
			final += "." + root

			for _, part := range parsedParts {
				final += "." + strcase.LowerCamelCase(part)
			}

			normalized[final] = v
		}
	}

	return normalized
}
