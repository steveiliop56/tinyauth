package decoders

import (
	"reflect"
	"regexp"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

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
			if i == 0 {
				final += kebabToCamel(part)
				continue
			}
			final += "." + kebabToCamel(part)
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

	re := regexp.MustCompile(`[A-Z]`)

	for field := range typeOfT.NumField() {
		if typeOfT.Field(field).Tag.Get("field") != "" {
			keys = append(keys, typeOfT.Field(field).Tag.Get("field"))
			continue
		}

		var key string

		for i, char := range typeOfT.Field(field).Name {
			if re.MatchString(string(char)) && i != 0 {
				key += "-" + strings.ToLower(string(char))
				continue
			}
			key += strings.ToLower(string(char))
		}

		keys = append(keys, key)
	}

	return keys
}

func kebabToCamel(input string) string {
	res := ""
	parts := strings.Split(input, "-")

	for i, part := range parts {
		if i == 0 {
			res += part
			continue
		}
		res += cases.Title(language.English).String(part)
	}

	return res
}
