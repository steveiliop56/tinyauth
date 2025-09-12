package decoders

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"tinyauth/internal/config"
	"tinyauth/internal/utils"

	"github.com/traefik/paerser/parser"
)

func DecodeEnv(env map[string]string) (config.Providers, error) {
	normalized := normalizeEnv(env, "tinyauth")

	node, err := decodeEnvsToNode(normalized, "tinyauth", "tinyauth_providers")

	if err != nil {
		return config.Providers{}, err
	}

	var providers config.Providers

	metaOpts := parser.MetadataOpts{TagName: "env", AllowSliceAsStruct: true}

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

func decodeEnvsToNode(env map[string]string, rootName string, filters ...string) (*parser.Node, error) {
	sorted := sortEnvKeys(env, filters)

	var node *parser.Node

	for i, k := range sorted {
		split := strings.SplitN(k, "_", 4)

		if split[0] != rootName {
			return nil, fmt.Errorf("invalid env root %s", split[0])
		}

		if slices.Contains(split, "") {
			return nil, fmt.Errorf("invalid element: %s", k)
		}

		if i == 0 {
			node = &parser.Node{}
		}

		decodeEnvToNode(node, split, env[k])
	}

	return node, nil
}

func decodeEnvToNode(root *parser.Node, path []string, value string) {
	if len(root.Name) == 0 {
		root.Name = path[0]
	}

	if !(len(path) > 1) {
		root.Value = value
		return
	}

	if n := containsEnvNode(root.Children, path[1]); n != nil {
		decodeEnvToNode(n, path[1:], value)
		return
	}

	child := &parser.Node{Name: path[1]}
	decodeEnvToNode(child, path[1:], value)
	root.Children = append(root.Children, child)
}

func containsEnvNode(node []*parser.Node, name string) *parser.Node {
	for _, n := range node {
		if strings.EqualFold(n.Name, name) {
			return n
		}
	}
	return nil
}

func sortEnvKeys(env map[string]string, filters []string) []string {
	var sorted []string

	for k := range env {
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

// normalizeEnv converts env vars from PROVIDERS_CLIENT1_CLIENT_ID to tinyauth_providers_client_clientId
func normalizeEnv(env map[string]string, rootName string) map[string]string {
	n := make(map[string]string)
	for k, v := range env {
		fk := strings.ToLower(k)
		fks := strings.SplitN(fk, "_", 3)
		fkb := ""
		for i, s := range strings.Split(fks[len(fks)-1], "_") {
			if i == 0 {
				fkb += s
				continue
			}
			fkb += utils.Capitalize(s)
		}
		fk = rootName + "_" + strings.Join(fks[:len(fks)-1], "_") + "_" + fkb
		n[fk] = v
	}
	return n
}
