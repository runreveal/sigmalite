// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigma

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type yamlRule struct {
	Title       string               `yaml:"title"`
	ID          string               `yaml:"id,omitempty"`
	Description string               `yaml:"description,omitempty"`
	LogSource   *LogSource           `yaml:"logsource"`
	Detection   map[string]yaml.Node `yaml:"detection"`
}

type yamlLogSource struct {
	Category   string `yaml:"category,omitempty"`
	Product    string `yaml:"product,omitempty"`
	Service    string `yaml:"service,omitempty"`
	Definition string `yaml:"definition,omitempty"`
}

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
		Description: doc.Description,
		ID:          doc.ID,
		LogSource:   new(LogSource),
		Detection:   new(Detection),
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

	return r, nil
}
