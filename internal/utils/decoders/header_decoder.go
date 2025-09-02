package decoders

import (
	"fmt"
	"sort"
	"strings"
	"tinyauth/internal/config"

	"github.com/traefik/paerser/parser"
)

// Based on: https://github.com/traefik/paerser/blob/master/parser/labels_decode.go (Apache 2.0 License)

func DecodeHeaders(headers map[string]string) (config.App, error) {
	var app config.App

	err := decodeHeadersHelper(headers, &app, "tinyauth")

	if err != nil {
		return config.App{}, err
	}

	return app, nil
}

func decodeHeadersHelper(headers map[string]string, element any, rootName string, filters ...string) error {
	node, err := decodeHeadersToNode(headers, rootName, filters...)

	if err != nil {
		return err
	}

	opts := parser.MetadataOpts{TagName: "header", AllowSliceAsStruct: true}
	err = parser.AddMetadata(element, node, opts)

	if err != nil {
		return err
	}

	return parser.Fill(element, node, parser.FillerOpts{AllowSliceAsStruct: true})
}

func decodeHeadersToNode(headers map[string]string, rootName string, filters ...string) (*parser.Node, error) {
	sortedKeys := sortKeys(headers, filters)

	var node *parser.Node

	for i, key := range sortedKeys {
		split := strings.Split(strings.ToLower(key), "-")

		if split[0] != rootName {
			return nil, fmt.Errorf("invalid header root %s", split[0])
		}

		var parts []string
		for _, v := range split {
			if v == "" {
				return nil, fmt.Errorf("invalid element: %s", key)
			}

			parts = append(parts, v)
		}

		if i == 0 {
			node = &parser.Node{}
		}

		decodeHeaderToNode(node, parts, headers[key])
	}

	return node, nil
}

func decodeHeaderToNode(root *parser.Node, path []string, value string) {
	if len(root.Name) == 0 {
		root.Name = path[0]
	}

	if len(path) > 1 {
		node := containsNode(root.Children, path[1])

		if node != nil {
			decodeHeaderToNode(node, path[1:], value)
		} else {
			child := &parser.Node{Name: path[1]}
			decodeHeaderToNode(child, path[1:], value)
			root.Children = append(root.Children, child)
		}
	} else {
		root.Value = value
	}
}

func containsNode(nodes []*parser.Node, name string) *parser.Node {
	for _, node := range nodes {
		if strings.EqualFold(node.Name, name) {
			return node
		}
	}
	return nil
}

func sortKeys(headers map[string]string, filters []string) []string {
	var sortedKeys []string

	for key := range headers {
		if len(filters) == 0 {
			sortedKeys = append(sortedKeys, key)
			continue
		}

		for _, filter := range filters {
			if len(key) >= len(filter) && strings.EqualFold(key[:len(filter)], filter) {
				sortedKeys = append(sortedKeys, key)
				continue
			}
		}
	}

	sort.Strings(sortedKeys)
	return sortedKeys
}
