// Copyright 2026 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigmalite

import (
	"fmt"
	"testing"
)

func nullTestRule(t *testing.T, selection string) *Rule {
	t.Helper()
	rule, err := ParseRule([]byte(fmt.Sprintf(
		"title: Null Semantics\nid: null-sem-test\nlogsource:\n  category: test\ndetection:\n  selection:\n%s  condition: selection\n",
		selection)))
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	return rule
}

// TestParseNullDistinctFromEmptyString: the parser must preserve the
// difference between a YAML null and an empty string — per the Sigma
// specification, "null cannot be part of a list of field values as it is its
// own type and therefore shares no type with any other value".
func TestParseNullDistinctFromEmptyString(t *testing.T) {
	tests := []struct {
		selection    string
		wantIsNull   bool
		wantPatterns []string
	}{
		{"    OptionalField: null\n", true, nil},
		{"    OptionalField: ~\n", true, nil},
		{"    OptionalField:\n", true, nil},
		{"    OptionalField: ''\n", false, []string{""}},
		{"    OptionalField: \"\"\n", false, []string{""}},
		{"    OptionalField: [null, 'x']\n", true, []string{"x"}},
		{"    OptionalField: 'null'\n", false, []string{"null"}},
	}
	for _, test := range tests {
		rule := nullTestRule(t, test.selection)
		expr := rule.Detection.Expr
		if named, ok := expr.(*NamedExpr); ok {
			expr = named.X
		}
		atom, ok := expr.(*SearchAtom)
		if !ok {
			t.Errorf("%q: Expr is %T, want *SearchAtom", test.selection, expr)
			continue
		}
		if atom.IsNull != test.wantIsNull {
			t.Errorf("%q: IsNull = %t, want %t", test.selection, atom.IsNull, test.wantIsNull)
		}
		if len(atom.Patterns) != len(test.wantPatterns) {
			t.Errorf("%q: Patterns = %q, want %q", test.selection, atom.Patterns, test.wantPatterns)
			continue
		}
		for i := range atom.Patterns {
			if atom.Patterns[i] != test.wantPatterns[i] {
				t.Errorf("%q: Patterns = %q, want %q", test.selection, atom.Patterns, test.wantPatterns)
				break
			}
		}
	}
}

// TestNullSemanticsMatches: "field: null" matches when the field is absent —
// regardless of the entry's message — and "field: ''" only when the field is
// present and empty.
func TestNullSemanticsMatches(t *testing.T) {
	tests := []struct {
		name      string
		selection string
		entry     *LogEntry
		want      bool
	}{
		{
			name:      "null matches absent field",
			selection: "    OptionalField: null\n",
			entry:     &LogEntry{Fields: map[string]string{"Image": "x"}},
			want:      true,
		},
		{
			name:      "null matches absent field regardless of message",
			selection: "    OptionalField: null\n",
			entry:     &LogEntry{Message: "some descriptive log text", Fields: map[string]string{"Image": "x"}},
			want:      true,
		},
		{
			name:      "null rejects populated field",
			selection: "    OptionalField: null\n",
			entry:     &LogEntry{Fields: map[string]string{"OptionalField": "populated"}},
			want:      false,
		},
		{
			name:      "null rejects populated field under different casing",
			selection: "    OptionalField: null\n",
			entry:     &LogEntry{Fields: map[string]string{"optionalfield": "populated"}},
			want:      false,
		},
		{
			name:      "null rejects present-but-empty field (empty string is not null)",
			selection: "    OptionalField: null\n",
			entry:     &LogEntry{Fields: map[string]string{"OptionalField": ""}},
			want:      false,
		},
		{
			name:      "empty string matches present empty field",
			selection: "    OptionalField: ''\n",
			entry:     &LogEntry{Message: "text", Fields: map[string]string{"OptionalField": ""}},
			want:      true,
		},
		{
			name:      "empty string rejects absent field",
			selection: "    OptionalField: ''\n",
			entry:     &LogEntry{Fields: map[string]string{"Image": "x"}},
			want:      false,
		},
		{
			name:      "empty string rejects populated field",
			selection: "    OptionalField: ''\n",
			entry:     &LogEntry{Fields: map[string]string{"OptionalField": "populated"}},
			want:      false,
		},
		{
			name:      "null list alternative matches absence",
			selection: "    OptionalField: [null, 'x']\n",
			entry:     &LogEntry{Fields: map[string]string{"Image": "x"}},
			want:      true,
		},
		{
			name:      "null list alternative matches listed value",
			selection: "    OptionalField: [null, 'x']\n",
			entry:     &LogEntry{Fields: map[string]string{"OptionalField": "x"}},
			want:      true,
		},
		{
			name:      "null list alternative rejects other values",
			selection: "    OptionalField: [null, 'x']\n",
			entry:     &LogEntry{Fields: map[string]string{"OptionalField": "y"}},
			want:      false,
		},
		{
			name:      "fielded atom does not fall back to message on absence",
			selection: "    CommandLine|contains: 'mimikatz'\n",
			entry:     &LogEntry{Message: "the operator ran mimikatz", Fields: map[string]string{"Image": "x"}},
			want:      false,
		},
	}
	for _, test := range tests {
		rule := nullTestRule(t, test.selection)
		if got := rule.Detection.Matches(test.entry, nil); got != test.want {
			t.Errorf("%s: Matches = %t, want %t", test.name, got, test.want)
		}
	}
}

type staticNullTestResolver map[string][]string

func (r staticNullTestResolver) Resolve(fieldName string, entry *LogEntry) []string {
	return r[fieldName]
}

// TestNullSemanticsWithFieldResolver: a resolver returning no values means
// the field is absent, so only a null atom matches; returned values are
// matched normally.
func TestNullSemanticsWithFieldResolver(t *testing.T) {
	nullRule := nullTestRule(t, "    OptionalField: null\n")
	emptyRule := nullTestRule(t, "    OptionalField: ''\n")
	entry := &LogEntry{Fields: map[string]string{}}

	absent := &MatchOptions{FieldResolver: staticNullTestResolver{}}
	if !nullRule.Detection.Matches(entry, absent) {
		t.Error("null atom must match when the resolver finds no field")
	}
	if emptyRule.Detection.Matches(entry, absent) {
		t.Error("empty-string atom must not match when the resolver finds no field")
	}

	populated := &MatchOptions{FieldResolver: staticNullTestResolver{"OptionalField": {"populated"}}}
	if nullRule.Detection.Matches(entry, populated) {
		t.Error("null atom must not match a resolver-supplied value")
	}

	empty := &MatchOptions{FieldResolver: staticNullTestResolver{"OptionalField": {""}}}
	if !emptyRule.Detection.Matches(entry, empty) {
		t.Error("empty-string atom must match a resolver-supplied empty value")
	}
}
