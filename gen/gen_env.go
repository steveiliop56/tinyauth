package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strings"

	"github.com/steveiliop56/tinyauth/internal/config"
)

type Path struct {
	Name        string
	Description string
	Value       any
}

func generateExampleEnv() {
	cfg := config.NewDefaultConfiguration()
	paths := make([]Path, 0)

	root := reflect.TypeOf(cfg).Elem()
	rootValue := reflect.ValueOf(cfg).Elem()
	rootPath := "TINYAUTH_"

	buildPaths(root, rootValue, rootPath, &paths)
	compiled := compileEnv(paths)

	err := os.Remove(".env.example")
	if err != nil {
		slog.Error("failed to remove example env file", "error", err)
		os.Exit(1)
	}

	err = os.WriteFile(".env.example", compiled, 0644)
	if err != nil {
		slog.Error("failed to write example env file", "error", err)
		os.Exit(1)
	}
}

func buildPaths(parent reflect.Type, parentValue reflect.Value, parentPath string, paths *[]Path) {
	for i := 0; i < parent.NumField(); i++ {
		field := parent.Field(i)
		fieldType := field.Type
		fieldValue := parentValue.Field(i)
		switch fieldType.Kind() {
		case reflect.Struct:
			childPath := parentPath + strings.ToUpper(field.Name) + "_"
			buildPaths(fieldType, fieldValue, childPath, paths)
		case reflect.Map:
			buildMapPaths(field, parentPath, paths)
		case reflect.Bool, reflect.String, reflect.Slice, reflect.Int:
			buildPath(field, fieldValue, parentPath, paths)
		default:
			slog.Info("unknown type", "type", fieldType.Kind())
		}
	}
}

func buildPath(field reflect.StructField, fieldValue reflect.Value, parent string, paths *[]Path) {
	desc := field.Tag.Get("description")
	yamlTag := field.Tag.Get("yaml")

	// probably internal logic, should be skipped
	if yamlTag == "-" {
		return
	}

	defaultValue := fieldValue.Interface()

	path := Path{
		Name:        parent + strings.ToUpper(field.Name),
		Description: desc,
	}

	switch fieldValue.Kind() {
	case reflect.Slice:
		sl, ok := defaultValue.([]string)
		if !ok {
			slog.Error("invalid default value", "value", defaultValue)
			return
		}
		path.Value = strings.Join(sl, ",")
	case reflect.String:
		st, ok := defaultValue.(string)
		if !ok {
			slog.Error("invalid default value", "value", defaultValue)
			return
		}
		// good idea to escape strings probably
		if st != "" {
			path.Value = fmt.Sprintf(`"%s"`, st)
		} else {
			path.Value = ""
		}
	default:
		path.Value = defaultValue
	}
	*paths = append(*paths, path)
}

func buildMapPaths(field reflect.StructField, parentPath string, paths *[]Path) {
	fieldType := field.Type

	if fieldType.Key().Kind() != reflect.String {
		slog.Info("unsupported map key type", "type", fieldType.Key().Kind())
		return
	}

	mapPath := parentPath + strings.ToUpper(field.Name) + "_NAME_"
	valueType := fieldType.Elem()

	if valueType.Kind() == reflect.Struct {
		zeroValue := reflect.New(valueType).Elem()
		buildPaths(valueType, zeroValue, mapPath, paths)
	}
}

func compileEnv(paths []Path) []byte {
	buffer := bytes.Buffer{}
	buffer.WriteString("# Tinyauth example configuration\n\n")

	for _, path := range paths {
		buffer.WriteString("# ")
		buffer.WriteString(path.Description)
		buffer.WriteString("\n")
		buffer.WriteString(path.Name)
		buffer.WriteString("=")
		fmt.Fprintf(&buffer, "%v", path.Value)
		buffer.WriteString("\n\n")
	}

	return buffer.Bytes()
}
