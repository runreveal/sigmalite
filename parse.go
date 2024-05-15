// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigma

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type yamlRule struct {
	Title          string               `yaml:"title"`
	ID             string               `yaml:"id,omitempty"`
	Related        []yamlRelation       `yaml:"related,omitempty"`
	Status         Status               `yaml:"status,omitempty"`
	Description    string               `yaml:"description,omitempty"`
	References     []string             `yaml:"references,omitempty"`
	Author         string               `yaml:"author,omitempty"`
	Date           Date                 `yaml:"date,omitempty"`
	Modified       Date                 `yaml:"modified,omitempty"`
	Tags           []string             `yaml:"tags,omitempty"`
	Level          Level                `yaml:"level,omitempty"`
	LogSource      *LogSource           `yaml:"logsource"`
	Detection      map[string]yaml.Node `yaml:"detection"`
	Fields         []string             `yaml:"fields,omitempty"`
	FalsePositives yaml.Node            `yaml:"falsepositives,omitempty"`
}

type yamlRelation struct {
	ID   string       `yaml:"id"`
	Type RelationType `yaml:"type"`
}

type yamlLogSource struct {
	Category   string `yaml:"category,omitempty"`
	Product    string `yaml:"product,omitempty"`
	Service    string `yaml:"service,omitempty"`
	Definition string `yaml:"definition,omitempty"`
}

// ParseRule parses a single Sigma detection format YAML document.
func ParseRule(data []byte) (*Rule, error) {
	doc := new(yamlRule)
	if err := yaml.Unmarshal(data, doc); err != nil {
		return nil, fmt.Errorf("parse sigma rule: %v", err)
	}
	if doc.Title == "" {
		return nil, fmt.Errorf("parse sigma rule: missing title")
	}
	r := &Rule{
		Title:       doc.Title,
		ID:          doc.ID,
		Status:      doc.Status,
		Description: doc.Description,
		References:  doc.References,
		Author:      doc.Author,
		Date:        doc.Date,
		Modified:    doc.Modified,
		Tags:        doc.Tags,
		Level:       doc.Level,

		LogSource: new(LogSource),
		Detection: new(Detection),

		Fields: doc.Fields,
	}

	// Technically the Sigma specification makes this required,
	// but leaves all the fields optional.
	// I'd rather treat an empty map the same as a missing one.
	if doc.LogSource != nil {
		r.LogSource.Category = doc.LogSource.Category
		r.LogSource.Product = doc.LogSource.Product
		r.LogSource.Service = doc.LogSource.Service
		r.LogSource.Definition = doc.LogSource.Definition
	}

	if doc.Detection == nil {
		return nil, fmt.Errorf("parse sigma rule %q: missing detection", r.Title)
	}
	var err error
	r.Detection, err = parseDetection(doc.Detection)
	if err != nil {
		return nil, fmt.Errorf("parse sigma rule %q: %v", r.Title, err)
	}

	if len(doc.Related) > 0 {
		r.Related = make([]Relation, 0, len(doc.Related))
		for i, rel := range doc.Related {
			if rel.ID == "" {
				return nil, fmt.Errorf("parse sigma rule %q: related[%d]: missing id", r.Title, i)
			}
			if rel.Type == "" {
				return nil, fmt.Errorf("parse sigma rule %q: related[%d]: missing type", r.Title, i)
			}
			r.Related = append(r.Related, Relation(rel))
		}
	}

	switch doc.FalsePositives.Kind {
	case 0:
	case yaml.ScalarNode:
		var s string
		if err := doc.FalsePositives.Decode(&s); err != nil {
			return nil, fmt.Errorf("parse sigma rule %q: false positives: %v", r.Title, err)
		}
		r.FalsePositives = []string{s}
	case yaml.SequenceNode:
		if err := doc.FalsePositives.Decode(&r.FalsePositives); err != nil {
			return nil, fmt.Errorf("parse sigma rule %q: false positives: %v", r.Title, err)
		}
	default:
		return nil, fmt.Errorf("parse sigma rule %q: false positives: unsupported value", r.Title)
	}

	return r, nil
}

func parseDetection(block map[string]yaml.Node) (*Detection, error) {
	docCondition, ok := block["condition"]
	if !ok {
		return nil, fmt.Errorf("missing detection condition")
	}
	var condition string
	if err := docCondition.Decode(&condition); err != nil {
		return nil, fmt.Errorf("condition: %v", err)
	}

	idents := make(map[string]*NamedExpr)
	for id, x := range block {
		if id == "condition" {
			continue
		}

		var result Expr
		switch x.Kind {
		case yaml.SequenceNode:
			container := new(OrExpr)
			for _, elem := range x.Content {
				switch elem.Kind {
				case yaml.ScalarNode:
					var s string
					if err := elem.Decode(&s); err != nil {
						return nil, fmt.Errorf("search identifier %q: %v", id, err)
					}
					container.X = append(container.X, &SearchAtom{
						Patterns: []string{s},
					})
				case yaml.MappingNode:
					y, err := parseSearchMap(elem)
					if err != nil {
						return nil, fmt.Errorf("search identifier %q: %v", id, err)
					}
					container.X = append(container.X, y)
				default:
					return nil, fmt.Errorf("search identifier %q: unsupported list value", id)
				}
			}
			switch len(container.X) {
			case 0:
				return nil, fmt.Errorf("search identifier %q: empty list", id)
			case 1:
				result = container.X[0]
			default:
				// TODO(soon): Convert an all-atoms container into a single atom.
				result = container
			}
		case yaml.MappingNode:
			y, err := parseSearchMap(&x)
			if err != nil {
				return nil, fmt.Errorf("search identifier %q: %v", id, err)
			}
			result = y
		default:
			return nil, fmt.Errorf("search identifier %q: unsupported value", id)
		}

		idents[id] = &NamedExpr{
			Name: id,
			X:    result,
		}
	}

	// TODO(soon): Support more complex expressions.
	named := idents[condition]
	if named == nil {
		return nil, fmt.Errorf("condition: undefined search identifier %q", condition)
	}
	return &Detection{
		Expr: named,
	}, nil
}

func parseSearchMap(node *yaml.Node) (Expr, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("not a map")
	}
	container := new(AndExpr)
	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]

		var k string
		if err := keyNode.Decode(&k); err != nil {
			return nil, err
		}
		atom := &SearchAtom{
			Field: k,
			// TODO(soon): Modifiers
		}

		// TODO(maybe): Handle integers differently?
		switch valueNode.Kind {
		case yaml.ScalarNode:
			var v string
			if err := valueNode.Decode(&v); err != nil {
				return nil, fmt.Errorf("%s: %v", k, err)
			}
			atom.Patterns = []string{v}
		case yaml.SequenceNode:
			if err := valueNode.Decode(&atom.Patterns); err != nil {
				return nil, fmt.Errorf("%s: %v", k, err)
			}
		default:
			return nil, fmt.Errorf("%s: unsupported value", k)
		}

		container.X = append(container.X, atom)
	}

	switch len(container.X) {
	case 0:
		return nil, fmt.Errorf("empty map")
	case 1:
		return container.X[0], nil
	default:
		return container, nil
	}
}
