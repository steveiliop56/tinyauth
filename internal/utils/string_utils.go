package utils

import (
	"strings"
)

func Capitalize(str string) string {
	if len(str) == 0 {
		return ""
	}
	return strings.ToUpper(string([]rune(str)[0])) + string([]rune(str)[1:])
}

func CoalesceToString(value any) string {
	switch v := value.(type) {
	case []any:
		strs := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				strs = append(strs, str)
				continue
			}
		}
		return strings.Join(strs, ",")
	case string:
		return v
	default:
		return ""
	}
}
