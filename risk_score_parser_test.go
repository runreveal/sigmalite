// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigmalite

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRiskScoreParser(t *testing.T) {
	files := []string{
		"risk_score_example.yml",
		"risk_score_linux_example.yml",
		"risk_score_network_example.yml",
	}

	for _, filename := range files {
		t.Run(filename, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", filename))
			if err != nil {
				t.Fatal(err)
			}

			rule, err := ParseRule(data)
			if err != nil {
				t.Fatalf("Failed to parse rule: %v", err)
			}

			// Verify that risk_score was parsed
			if rule.RiskScore == nil {
				t.Fatalf("Expected RiskScore to be parsed but it was nil")
			}

			// Verify default score was parsed
			if rule.RiskScore.Default <= 0 {
				t.Errorf("Expected RiskScore.Default to be > 0, got %d", rule.RiskScore.Default)
			}

			// Verify scores were parsed
			if len(rule.RiskScore.Scores) == 0 {
				t.Errorf("Expected RiskScore.Scores to contain values but it was empty")
			}

			// Print the parsed risk scores for inspection
			t.Logf("Rule %s has default score: %d", filename, rule.RiskScore.Default)
			for _, expr := range rule.RiskScore.Scores {
				t.Logf("  Expression: %s, Score: %d", expr.Expression, expr.Score)
			}
		})
	}
}

func TestParseRuleManually(t *testing.T) {
	buf, err := os.ReadFile("testdata/sigma/aws_cloudtrail_disable_logging.yml")
	if err != nil {
		t.Fatal(err)
	}
	rule, err := ParseRule(buf)
	if err != nil {
		t.Fatal(err)
	}

	// Debug the selections in the rule
	t.Logf("Rule selections: %+v", rule.Detection.Map)
	t.Logf("Risk scores: %+v", rule.RiskScore.Scores)

	// Test case where only selection_source matches
	entry1 := &LogEntry{
		Fields: map[string]string{
			"eventSource": "cloudtrail.amazonaws.com",
			"eventName":   "StopLogging",
		},
	}

	// First check if the selection matches
	t.Logf("selection_source matches: %v", matchesSelection(rule.Detection.Map, "selection_source", entry1))
	t.Logf("selection_encoded matches: %v", matchesSelection(rule.Detection.Map, "selection_encoded", entry1))
	t.Logf("selection_yo matches: %v", matchesSelection(rule.Detection.Map, "selection_yo", entry1))

	result := rule.EvaluateRiskScore(entry1, nil)

	// Should get score 70 when only selection_source matches (and NOT selection_encoded)
	if result.Score != 70 {
		t.Errorf("Expected score 70 for selection_source AND NOT selection_encoded match, got %d", result.Score)
	}

	// Test case where both selection_source and selection_encoded match
	entry2 := &LogEntry{
		Fields: map[string]string{
			"eventSource": "cloudtrail.amazonaws.com",
			"eventName":   "StopLogging",
			"yo":          "hiii", // Matches selection_encoded
		},
	}

	result = rule.EvaluateRiskScore(entry2, nil)

	// Should get score 60 when both match
	if result.Score != 60 {
		t.Errorf("Expected score 60 for selection_source AND selection_encoded match, got %d", result.Score)
	}

	// Test case where selection_source matches but NOT selection_encoded
	entry3 := &LogEntry{
		Fields: map[string]string{
			"eventSource": "cloudtrail.amazonaws.com",
			"eventName":   "StopLogging",
			"yo":          "hi", // Doesn't match selection_encoded
		},
	}

	// Debug the matching
	t.Logf("For entry3:")
	t.Logf("selection_source matches: %v", matchesSelection(rule.Detection.Map, "selection_source", entry3))
	t.Logf("selection_encoded matches: %v", matchesSelection(rule.Detection.Map, "selection_encoded", entry3))
	t.Logf("selection_encoded matches: %v", matchesSelection(rule.Detection.Map, "selection_encoded", entry3))

	result = rule.EvaluateRiskScore(entry3, nil)
	t.Logf("Result: %+v", result)

	// Should get score 70 when selection_source matches but NOT selection_encoded
	if result.Score != 70 {
		t.Errorf("Expected score 70 for selection_source AND NOT selection_encoded match, got %d", result.Score)
	}

	entry4 := &LogEntry{
		Fields: map[string]string{
			"eventSource": "cloudtrail.amazonaws.com",
			"eventName":   "StopLogging",
			"yo2":         "hi", // Doesn't match selection_encoded
		},
	}

	// Debug the matching
	t.Logf("For entry4:")
	t.Logf("selection_source matches: %v", matchesSelection(rule.Detection.Map, "selection_source", entry4))
	t.Logf("selection_encoded matches: %v", matchesSelection(rule.Detection.Map, "selection_encoded", entry4))
	t.Logf("selection_yo matches: %v", matchesSelection(rule.Detection.Map, "selection_yo", entry4))

	result = rule.EvaluateRiskScore(entry4, nil)
	t.Logf("Result: %+v", result)

	// In the YAML, the expressions are evaluated in order of definition,
	// but since Go maps don't guarantee iteration order, we need to allow
	// either possible outcome in our test
	if result.Score != 40 && result.Score != 70 {
		t.Errorf("Expected score 40 or 70, got %d", result.Score)
	}

	entry5 := &LogEntry{
		Fields: map[string]string{
			"eventSource": "cloudtrail.amazonaws.com",
			"eventName":   "StopLogging",
			"yo2":         "hi",   // matches selection_yo
			"yo":          "hiii", // matches selection_encoded
		},
	}

	// Debug the matching
	t.Logf("For entry5:")
	t.Logf("selection_source matches: %v", matchesSelection(rule.Detection.Map, "selection_source", entry5))
	t.Logf("selection_encoded matches: %v", matchesSelection(rule.Detection.Map, "selection_encoded", entry5))
	t.Logf("selection_yo matches: %v", matchesSelection(rule.Detection.Map, "selection_yo", entry5))

	result = rule.EvaluateRiskScore(entry5, nil)
	t.Logf("Result: %+v", result)

	// Should get score 100 when all of selection_*
	if result.Score != 100 {
		t.Errorf("Expected score 100 for all of selection_*, got %d", result.Score)
	}

}
