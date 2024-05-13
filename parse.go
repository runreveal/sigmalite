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
	docCondition, ok := doc.Detection["condition"]
	if !ok {
		return nil, fmt.Errorf("parse sigma rule %q: missing detection condition", r.Title)
	}
	if err := docCondition.Decode(&r.Detection.Condition); err != nil {
		return nil, fmt.Errorf("parse sigma rule %q: condition: %v", r.Title, err)
	}
	for id, x := range doc.Detection {
		if id == "condition" {
			continue
		}
		if r.Detection.Identifiers == nil {
			r.Detection.Identifiers = make(map[string]*SearchIdentifier)
		}
		r.Detection.Identifiers[id] = new(SearchIdentifier)
		// TODO(soon)
		_ = x
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
