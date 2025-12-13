// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigmalite

import (
	"strings"
	"testing"
)

func TestExplainBasic(t *testing.T) {
	detection := &Detection{
		Expr: &SearchAtom{
			Field:    "EventId",
			Patterns: []string{"1234"},
		},
	}

	entry := &LogEntry{
		Fields: map[string]string{
			"EventId": "1234",
		},
	}

	opts := &MatchOptions{EnableExplanation: true}
	result := detection.Matches(entry, opts)

	if !result.Matched {
		t.Error("Expected match")
	}
	if result.Explanation == "" {
		t.Error("Expected non-empty explanation")
	}
	if !strings.Contains(result.Explanation, "EventId") {
		t.Error("Explanation should mention EventId field")
	}
	t.Logf("Explanation:\n%s", result.Explanation)
}

func TestExplainAndExpressionFailure(t *testing.T) {
	detection := &Detection{
		Expr: &AndExpr{
			X: []Expr{
				&SearchAtom{Field: "EventId", Patterns: []string{"1234"}},
				&SearchAtom{Field: "User", Patterns: []string{"admin"}},
			},
		},
	}

	entry := &LogEntry{
		Fields: map[string]string{
			"EventId": "1234",
			"User":    "guest",
		},
	}

	opts := &MatchOptions{EnableExplanation: true}
	result := detection.Matches(entry, opts)

	if result.Matched {
		t.Error("Expected no match")
	}
	if !strings.Contains(result.Explanation, "User") {
		t.Error("Explanation should mention User field")
	}
	if !strings.Contains(result.Explanation, "✗") {
		t.Error("Explanation should show failure symbol")
	}
	t.Logf("Explanation:\n%s", result.Explanation)
}

func TestExplainOrExpression(t *testing.T) {
	detection := &Detection{
		Expr: &OrExpr{
			X: []Expr{
				&SearchAtom{Field: "EventId", Patterns: []string{"1234"}},
				&SearchAtom{Field: "EventId", Patterns: []string{"5678"}},
			},
		},
	}

	entry := &LogEntry{
		Fields: map[string]string{
			"EventId": "1234",
		},
	}

	opts := &MatchOptions{EnableExplanation: true}
	result := detection.Matches(entry, opts)

	if !result.Matched {
		t.Error("Expected match")
	}
	if !strings.Contains(result.Explanation, "[OR]") {
		t.Error("Explanation should mention OR")
	}
	t.Logf("Explanation:\n%s", result.Explanation)
}

func TestExplainNotExpression(t *testing.T) {
	detection := &Detection{
		Expr: &NotExpr{
			X: &SearchAtom{Field: "User", Patterns: []string{"admin"}},
		},
	}

	entry := &LogEntry{
		Fields: map[string]string{
			"User": "guest",
		},
	}

	opts := &MatchOptions{EnableExplanation: true}
	result := detection.Matches(entry, opts)

	if !result.Matched {
		t.Error("Expected match (NOT admin)")
	}
	if !strings.Contains(result.Explanation, "[NOT]") {
		t.Error("Explanation should mention NOT")
	}
	if !strings.Contains(result.Explanation, "negated") {
		t.Error("Explanation should mention negation")
	}
	t.Logf("Explanation:\n%s", result.Explanation)
}

func TestExplainMissingField(t *testing.T) {
	detection := &Detection{
		Expr: &SearchAtom{
			Field:    "MissingField",
			Patterns: []string{"value"},
		},
	}

	entry := &LogEntry{
		Fields: map[string]string{
			"OtherField": "other",
		},
	}

	opts := &MatchOptions{EnableExplanation: true}
	result := detection.Matches(entry, opts)

	if result.Matched {
		t.Error("Expected no match")
	}
	if !strings.Contains(result.Explanation, "not found") {
		t.Error("Explanation should mention field not found")
	}
	t.Logf("Explanation:\n%s", result.Explanation)
}

func TestExplainCaseInsensitive(t *testing.T) {
	detection := &Detection{
		Expr: &SearchAtom{
			Field:    "eventid",
			Patterns: []string{"1234"},
		},
	}

	entry := &LogEntry{
		Fields: map[string]string{
			"EventId": "1234",
		},
	}

	opts := &MatchOptions{EnableExplanation: true}
	result := detection.Matches(entry, opts)

	if !result.Matched {
		t.Error("Expected match (case-insensitive)")
	}
	if !strings.Contains(result.Explanation, "case-insensitive") {
		t.Error("Explanation should mention case-insensitive match")
	}
	t.Logf("Explanation:\n%s", result.Explanation)
}

func TestExplainMessage(t *testing.T) {
	detection := &Detection{
		Expr: &SearchAtom{
			Field:    "",
			Patterns: []string{"*error*"},
		},
	}

	entry := &LogEntry{
		Message: "An error occurred",
	}

	opts := &MatchOptions{EnableExplanation: true}
	result := detection.Matches(entry, opts)

	if !result.Matched {
		t.Error("Expected match on message")
	}
	if !strings.Contains(result.Explanation, "message") {
		t.Error("Explanation should mention message matching")
	}
	t.Logf("Explanation:\n%s", result.Explanation)
}

func TestExplainDisabled(t *testing.T) {
	detection := &Detection{
		Expr: &SearchAtom{
			Field:    "EventId",
			Patterns: []string{"1234"},
		},
	}

	entry := &LogEntry{
		Fields: map[string]string{
			"EventId": "1234",
		},
	}

	opts := &MatchOptions{EnableExplanation: false}
	result := detection.Matches(entry, opts)

	if !result.Matched {
		t.Error("Expected match")
	}
	if result.Explanation != "" {
		t.Error("Expected empty explanation when disabled")
	}
}

func TestExplainNamedExpression(t *testing.T) {
	detection := &Detection{
		Expr: &NamedExpr{
			Name: "selection",
			X: &SearchAtom{
				Field:    "EventId",
				Patterns: []string{"1234"},
			},
		},
	}

	entry := &LogEntry{
		Fields: map[string]string{
			"EventId": "1234",
		},
	}

	opts := &MatchOptions{EnableExplanation: true}
	result := detection.Matches(entry, opts)

	if !result.Matched {
		t.Error("Expected match")
	}
	if !strings.Contains(result.Explanation, "selection") {
		t.Error("Explanation should mention named expression 'selection'")
	}
	t.Logf("Explanation:\n%s", result.Explanation)
}

func TestExplainComplexRule(t *testing.T) {
	detection := &Detection{
		Expr: &AndExpr{
			X: []Expr{
				&NamedExpr{
					Name: "selection",
					X: &SearchAtom{
						Field:    "EventId",
						Patterns: []string{"4624"},
					},
				},
				&NotExpr{
					X: &NamedExpr{
						Name: "filter",
						X: &SearchAtom{
							Field:    "User",
							Patterns: []string{"SYSTEM"},
						},
					},
				},
			},
		},
	}

	entry := &LogEntry{
		Fields: map[string]string{
			"EventId": "4624",
			"User":    "admin",
		},
	}

	opts := &MatchOptions{EnableExplanation: true}
	result := detection.Matches(entry, opts)

	if !result.Matched {
		t.Error("Expected match")
	}
	if !strings.Contains(result.Explanation, "selection") {
		t.Error("Explanation should mention 'selection'")
	}
	if !strings.Contains(result.Explanation, "filter") {
		t.Error("Explanation should mention 'filter'")
	}
	t.Logf("Explanation:\n%s", result.Explanation)
}
