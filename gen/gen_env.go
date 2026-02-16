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
	}

	err = os.WriteFile(".env.example", compiled, 0644)
	if err != nil {
		slog.Error("failed to write example env file", "error", err)
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
		case reflect.Bool:
			buildPath(field, fieldValue, parentPath, paths)
		case reflect.String:
			buildPath(field, fieldValue, parentPath, paths)
		case reflect.Slice:
			buildPath(field, fieldValue, parentPath, paths)
		case reflect.Int:
			buildPath(field, fieldValue, parentPath, paths)
		case reflect.Map:
			buildMapPaths(field, parentPath, paths)
		default:
			slog.Info("unknown type", "type", fieldType.Kind())
		}

	}
}

func buildPath(field reflect.StructField, fieldValue reflect.Value, parent string, paths *[]Path) {
	desc := field.Tag.Get("description")
	defaultValue := fieldValue.Interface()
	path := Path{
		Name:        parent + strings.ToUpper(field.Name),
		Description: desc,
		Value:       defaultValue,
	}
	*paths = append(*paths, path)
}

func buildMapPaths(field reflect.StructField, parentPath string, paths *[]Path) {
	fieldType := field.Type

	if fieldType.Key().Kind() != reflect.String {
		slog.Info("unsupported map key type", "type", fieldType.Key().Kind())
		return
	}

	mapPath := parentPath + strings.ToUpper(field.Name) + "_[NAME]_"
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
		buffer.WriteString("\n")
	}

	return buffer.Bytes()
}
