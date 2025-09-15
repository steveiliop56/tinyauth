package decoders

import (
	"reflect"
	"strings"
	"tinyauth/internal/config"
)

func NormalizeKeys(keys map[string]string, rootName string, sep string) map[string]string {
	normalized := make(map[string]string)
	knownKeys := getKnownKeys()

	for k, v := range keys {
		var finalKey []string
		var suffix string
		var camelClientName string
		var camelField string

		finalKey = append(finalKey, rootName)
		finalKey = append(finalKey, "providers")
		cebabKey := strings.ToLower(k)

		for _, known := range knownKeys {
			if strings.HasSuffix(cebabKey, strings.ReplaceAll(known, "-", sep)) {
				suffix = known
				break
			}
		}

		if suffix == "" {
			continue
		}

		clientNameParts := strings.Split(strings.TrimPrefix(strings.TrimSuffix(cebabKey, sep+strings.ReplaceAll(suffix, "-", sep)), "providers"+sep), sep)

		for i, p := range clientNameParts {
			if i == 0 {
				camelClientName += p
				continue
			}
			if p == "" {
				continue
			}
			camelClientName += strings.ToUpper(string([]rune(p)[0])) + string([]rune(p)[1:])
		}

		finalKey = append(finalKey, camelClientName)

		filedParts := strings.Split(suffix, "-")

		for i, p := range filedParts {
			if i == 0 {
				camelField += p
				continue
			}
			if p == "" {
				continue
			}
			camelField += strings.ToUpper(string([]rune(p)[0])) + string([]rune(p)[1:])
		}

		finalKey = append(finalKey, camelField)
		normalized[strings.Join(finalKey, ".")] = v
	}

	return normalized
}

func getKnownKeys() []string {
	var known []string

	p := config.OAuthServiceConfig{}
	v := reflect.ValueOf(p)
	typeOfP := v.Type()

	for field := range typeOfP.NumField() {
		known = append(known, typeOfP.Field(field).Tag.Get("key"))
	}

	return known
}
