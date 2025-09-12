package decoders

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"tinyauth/internal/config"

	"github.com/traefik/paerser/parser"
)

func DecodeFlags(flags map[string]string) (config.Providers, error) {
	normalized := normalizeFlags(flags, "tinyauth")

	node, err := decodeFlagsToNode(normalized, "tinyauth", "tinyauth_providers")

	if err != nil {
		return config.Providers{}, err
	}

	var providers config.Providers

	metaOpts := parser.MetadataOpts{TagName: "flag", AllowSliceAsStruct: true}

	err = parser.AddMetadata(&providers, node, metaOpts)

	if err != nil {
		return config.Providers{}, err
	}

	err = parser.Fill(&providers, node, parser.FillerOpts{AllowSliceAsStruct: true})

	if err != nil {
		return config.Providers{}, err
	}

	return providers, nil
}

func decodeFlagsToNode(flags map[string]string, rootName string, filters ...string) (*parser.Node, error) {
	sorted := sortFlagKeys(flags, filters)

	var node *parser.Node

	for i, k := range sorted {
		split := strings.SplitN(k, "_", 4)

		if split[0] != rootName {
			return nil, fmt.Errorf("invalid flag root %s", split[0])
		}

		if slices.Contains(split, "") {
			return nil, fmt.Errorf("invalid element: %s", k)
		}

		if i == 0 {
			node = &parser.Node{}
		}

		decodeFlagToNode(node, split, flags[k])
	}

	return node, nil
}

func decodeFlagToNode(root *parser.Node, path []string, value string) {
	if len(root.Name) == 0 {
		root.Name = path[0]
	}

	if !(len(path) > 1) {
		root.Value = value
		return
	}

	if n := containsFlagNode(root.Children, path[1]); n != nil {
		decodeFlagToNode(n, path[1:], value)
		return
	}

	child := &parser.Node{Name: path[1]}
	decodeFlagToNode(child, path[1:], value)
	root.Children = append(root.Children, child)
}

func containsFlagNode(node []*parser.Node, name string) *parser.Node {
	for _, n := range node {
		if strings.EqualFold(n.Name, name) {
			return n
		}
	}
	return nil
}

func sortFlagKeys(flags map[string]string, filters []string) []string {
	var sorted []string

	for k := range flags {
		if len(filters) == 0 {
			sorted = append(sorted, k)
			continue
		}

		for _, f := range filters {
			if strings.HasPrefix(k, f) {
				sorted = append(sorted, k)
				break
			}
		}
	}

	sort.Strings(sorted)
	return sorted
}

// normalizeFlags converts flags from --providers-client-client-id to tinyauth_providers_client_clientId
func normalizeFlags(flags map[string]string, rootName string) map[string]string {
	n := make(map[string]string)
	for k, v := range flags {
		fk := strings.TrimPrefix(k, "--")
		fks := strings.SplitN(fk, "-", 3)
		fkb := ""
		for i, s := range strings.Split(fks[len(fks)-1], "-") {
			if i == 0 {
				fkb += s
				continue
			}
			fkb += strings.ToUpper(string([]rune(s)[0])) + string([]rune(s)[1:])
		}
		fk = rootName + "_" + strings.Join(fks[:len(fks)-1], "_") + "_" + fkb
		n[fk] = v
	}
	return n
}
