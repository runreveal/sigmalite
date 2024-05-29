// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

// Package sigma provides a parser and an execution engine
// for the [Sigma detection format].
//
// [Sigma detection format]: https://sigmahq.io/
package sigma

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Rule represents a parsed Sigma rule file.
type Rule struct {
	// Title is a short description of what the rule detects.
	Title string
	// ID is an optional globally unique identifier for the rule.
	ID string
	// Related is a set of references to other rules.
	Related []Relation
	// Status is an optional indicator of the stability of the rule.
	Status Status
	// Description is a long-form description of what the rule detects.
	Description string
	// References is a set of references that the rule was derived from.
	// By convention, this is a set of URLs.
	References []string
	// Author is the creator of the rule.
	Author string
	// Date is the creation date of the rule.
	Date Date
	// Modified is the last modification date of the rule.
	// By convention, Modified is updated whenever
	// the Detection, Level, LogSource, or Title is changed,
	// or whenever Status changes to [Deprecated].
	Modified Date
	// Tags is a set of categories applied to the rule.
	// See https://github.com/SigmaHQ/sigma-specification/blob/main/Tags_specification.md
	// for more details.
	Tags []string
	// Level indicates the criticality of the rule.
	Level Level

	// LogSource describes the log data on which the detection is meant to be applied to.
	LogSource *LogSource
	// Detection describes the pattern that a rule is matching on.
	Detection *Detection

	// Fields is a list of log fields that could be interesting in further analysis of the event
	// and should be displayed to the analyst.
	Fields []string
	// FalsePositives is a list of known false positives that may occur.
	FalsePositives []string

	// Extra is a set of YAML nodes for the unprocessed top-level fields.
	Extra map[string]Decoder
}

// Implementation note:
// The Decoder interface exists so that *yaml.Node is not part of the public interface of this package.
// Applications can type-assert if they really want,
// but that will naturally break or permit multiple types as desired.

// A Decoder is a value that can be decoded into a Go value.
type Decoder interface {
	Decode(v any) error
}

// LogSource describes the log data on which a [Detection] is meant to be applied to.
type LogSource struct {
	Category   string
	Product    string
	Service    string
	Definition string
}

// LogEntry represents an entry that a [Rule] can match on.
type LogEntry struct {
	Message string
	Fields  map[string]string
}

// MatchOptions are the parameters to [Detection.Matches] and [Expr.ExprMatches].
type MatchOptions struct {
	Placeholders map[string][]string
}

// Detection describes the pattern that a [Rule] is matching on.
type Detection struct {
	Expr Expr
}

// Matches reports whether the entry matches the detection's expression.
func (d *Detection) Matches(entry *LogEntry, opts *MatchOptions) bool {
	return d.Expr.ExprMatches(entry, opts)
}

// An Expr is a sub-expression inside of a [Detection].
//
// ExprMatches reports whether an entry matches the expression.
// Implementations of ExprMatches must be safe to call concurrently
// from multiple goroutines.
type Expr interface {
	ExprMatches(*LogEntry, *MatchOptions) bool
}

// NamedExpr is an [Expr] that has a name.
// These are referred to as "search identifiers" in the specification.
type NamedExpr struct {
	Name string
	X    Expr
}

func (n *NamedExpr) ExprMatches(entry *LogEntry, opts *MatchOptions) bool {
	return n.X.ExprMatches(entry, opts)
}

// NotExpr is a negated [Expr].
type NotExpr struct {
	X Expr
}

func (x *NotExpr) ExprMatches(entry *LogEntry, opts *MatchOptions) bool {
	return !x.X.ExprMatches(entry, opts)
}

// AndExpr is an [Expr] is an expression
// that evaluates to true if and only if all of its sub-expressions evaluate to true.
type AndExpr struct {
	X []Expr
}

func (a *AndExpr) ExprMatches(entry *LogEntry, opts *MatchOptions) bool {
	for _, x := range a.X {
		if !x.ExprMatches(entry, opts) {
			return false
		}
	}
	return true
}

// OrExpr is an [Expr] is an expression
// that evaluates to true if at least one of its sub-expressions evaluate to true.
type OrExpr struct {
	X []Expr
}

func (o *OrExpr) ExprMatches(entry *LogEntry, opts *MatchOptions) bool {
	for _, x := range o.X {
		if x.ExprMatches(entry, opts) {
			return true
		}
	}
	return false
}

// A SearchAtom is an [Expr] that matches against a single field.
type SearchAtom struct {
	// Field is the name of the field to match against.
	// If empty, then this matches against the message.
	Field string
	// Modifiers is a sequence of zero or more modifiers to apply against the field
	// before checking Patterns.
	Modifiers []string
	// Patterns is the set of patterns to check against the field.
	// If one of them matches, then the field matches this atom.
	Patterns []string

	mu                sync.RWMutex
	compiledIsMessage bool
	compiledModifiers []string
	compiledPatterns  []string
	compiled          compiledSearchAtom
}

type compiledSearchAtom struct {
	regexp []*regexp.Regexp
	cidr   []netip.Prefix
}

// Validate returns an error if the search atom won't match
// because the modifiers or patterns are invalid.
func (atom *SearchAtom) Validate() error {
	if len(atom.Patterns) == 0 {
		return fmt.Errorf("no patterns")
	}

	const (
		globPattern = iota
		rePattern
		cidr
	)

	patternType := globPattern
	expand := false
	for i, mod := range atom.Modifiers {
		switch mod {
		case "re":
			patternType = rePattern
			if len(atom.Modifiers) != 1 || (len(atom.Modifiers) == 2 && i == 1 && atom.Modifiers[0] == "expand") {
				return fmt.Errorf("re must be only modifier")
			}
		case "cidr":
			patternType = cidr
			if len(atom.Modifiers) != 1 || (len(atom.Modifiers) == 2 && i == 1 && atom.Modifiers[0] == "expand") {
				return fmt.Errorf("cidr must be only modifier")
			}
		case "contains", "all", "startswith", "endswith", "windash":
			// No special handling required.
		case "expand":
			expand = true
			if i != 0 {
				return fmt.Errorf("expand can only be the first modifier")
			}
			for _, placeholder := range atom.Patterns {
				if _, ok := cutPlaceholder(placeholder); !ok {
					return fmt.Errorf("placeholder %q must start and end with '%%'", placeholder)
				}
			}
		default:
			return fmt.Errorf("unknown modifier %q", mod)
		}
	}

	// Validate static patterns.
	if !expand {
		switch patternType {
		case rePattern:
			for i, pat := range atom.Patterns {
				if _, err := regexp.Compile(pat); err != nil {
					return fmt.Errorf("pattern %d: %v", i+1, err)
				}
			}
		case cidr:
			for i, pat := range atom.Patterns {
				if _, err := netip.ParsePrefix(pat); err != nil {
					return fmt.Errorf("pattern %d: %v", i+1, err)
				}
			}
		}
	}
	return nil
}

func (atom *SearchAtom) expandPatterns(placeholders map[string][]string) []string {
	if len(atom.Modifiers) > 0 && atom.Modifiers[0] == "expand" {
		var patterns []string
		for _, placeholder := range atom.Patterns {
			name, ok := cutPlaceholder(placeholder)
			if !ok {
				continue
			}
			patterns = append(patterns, placeholders[name]...)
		}
		return patterns
	}
	return atom.Patterns
}

func (atom *SearchAtom) ExprMatches(entry *LogEntry, opts *MatchOptions) bool {
	if err := atom.Validate(); err != nil {
		return false
	}
	field := entry.Message
	if atom.Field != "" {
		field = entry.Fields[atom.Field]
	}
	var placeholders map[string][]string
	if opts != nil {
		placeholders = opts.Placeholders
	}
	return atom.compile(placeholders).matches(field)
}

func (atom compiledSearchAtom) matches(field string) bool {
	if len(atom.regexp)+len(atom.cidr) == 0 {
		return false
	}

	// Regexps are chained by AND.
	for _, pat := range atom.regexp {
		if !pat.MatchString(field) {
			return false
		}
	}

	if len(atom.cidr) == 0 {
		return true
	}
	// CIDRs are chained by OR.
	addr, err := netip.ParseAddr(field)
	if err != nil {
		return false
	}
	for _, prefix := range atom.cidr {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (atom *SearchAtom) compile(placeholders map[string][]string) compiledSearchAtom {
	patterns := atom.expandPatterns(placeholders)
	if len(patterns) == 0 {
		// Can happen if the placeholders are invalid.
		return compiledSearchAtom{}
	}

	// Common case: we already compiled the atom.
	atom.mu.RLock()
	if atom.lockedCompileUpToDate(patterns) {
		compiled := atom.compiled
		atom.mu.RUnlock()
		return compiled
	}
	atom.mu.RUnlock()

	// Compile a new regular expression
	// (outside the critical section to reduce contention).
	var compiled compiledSearchAtom
	switch {
	case slices.Contains(atom.Modifiers, "cidr"):
		compiled.cidr = make([]netip.Prefix, 0, len(patterns))
		for _, pat := range patterns {
			prefix, err := netip.ParsePrefix(pat)
			if err != nil {
				continue
			}
			compiled.cidr = append(compiled.cidr, prefix)
		}
	case slices.Contains(atom.Modifiers, "all"):
		compiled.regexp = make([]*regexp.Regexp, 0, len(patterns))
		sb := new(strings.Builder)
		for _, pat := range patterns {
			sb.Reset()
			if appendPatternRegexp(sb, pat, atom.Modifiers, atom.isMessage()) {
				compiled.regexp = append(compiled.regexp, regexp.MustCompile(sb.String()))
			}
		}
	default:
		sb := new(strings.Builder)
		first := true
		for _, pat := range patterns {
			if !first {
				sb.WriteString("|")
			}
			if appendPatternRegexp(sb, pat, atom.Modifiers, atom.isMessage()) {
				first = false
			}
		}
		compiled.regexp = []*regexp.Regexp{regexp.MustCompile(sb.String())}
	}
	modifiersCopy := slices.Clone(atom.Modifiers)
	patternsCopy := slices.Clone(patterns)

	// Update cache.
	atom.mu.Lock()
	if !atom.lockedCompileUpToDate(patterns) {
		atom.compiledIsMessage = atom.isMessage()
		atom.compiledModifiers = modifiersCopy
		atom.compiledPatterns = patternsCopy
		atom.compiled = compiled
	}
	atom.mu.Unlock()

	return compiled
}

func (atom *SearchAtom) isMessage() bool {
	return atom.Field == ""
}

func (atom *SearchAtom) lockedCompileUpToDate(patterns []string) bool {
	return atom.isMessage() == atom.compiledIsMessage &&
		slices.Equal(atom.compiledPatterns, patterns) &&
		slices.Equal(atom.compiledModifiers, atom.compiledModifiers)
}

// appendPatternRegexp writes a regular expression equivalent to pattern
// to the given string builder.
// appendPatternRegexp assumes that the pattern is valid.
// appendPatternRegexp reports whether the pattern was valid.
func appendPatternRegexp(sb *strings.Builder, pattern string, modifiers []string, isMessage bool) bool {
	if slices.Contains(modifiers, "re") {
		if _, err := regexp.Compile(pattern); err != nil {
			return false
		}
		sb.WriteString("(?:")
		sb.WriteString(pattern)
		sb.WriteString(")")
		return true
	}

	contains := slices.Contains(modifiers, "contains")

	sb.WriteString("(?i:") // Case-insensitive, non-capturing group.
	if !isMessage && !contains && !slices.Contains(modifiers, "endswith") {
		sb.WriteString("^")
	}
	sb.WriteString("(?:")

	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '?':
			sb.WriteString(".")
		case '*':
			sb.WriteString(".*")
		case '\\':
			if i+1 >= len(pattern) {
				sb.WriteString(`\\`)
				continue
			}
			switch pattern[i+1] {
			case '?', '*', '\\':
				sb.WriteByte('\\')
				sb.WriteByte(pattern[i+1])
				i++
			default:
				// "Plain backslash not followed by a wildcard can be expressed as single \".
				sb.WriteString(`\\`)
			}
		default:
			appendQuoteMeta(sb, pattern[i:i+1])
		}
	}

	if slices.Contains(modifiers, "windash") {
		sb.WriteString("|")
		for i := 0; i < len(pattern); i++ {
			switch c := pattern[i]; c {
			case '?':
				sb.WriteString(".")
			case '*':
				sb.WriteString(".*")
			case '-':
				sb.WriteString("/")
			case '\\':
				if i+1 >= len(pattern) {
					sb.WriteString(`\\`)
					continue
				}
				switch pattern[i+1] {
				case '?', '*', '\\':
					sb.WriteByte('\\')
					sb.WriteByte(pattern[i+1])
					i++
				default:
					// "Plain backslash not followed by a wildcard can be expressed as single \".
					sb.WriteString(`\\`)
				}
			default:
				appendQuoteMeta(sb, pattern[i:i+1])
			}
		}
	}

	sb.WriteString(")")
	if !isMessage && !contains && !slices.Contains(modifiers, "startswith") {
		sb.WriteString("$")
	}
	sb.WriteString(")") // Close non-capturing group.
	return true
}

func cutPlaceholder(s string) (_ string, ok bool) {
	if len(s) < 2 || s[0] != '%' || s[len(s)-1] != '%' {
		return "", false
	}
	return s[1 : len(s)-1], true
}

// Status is an enumeration of [Rule] stability classifications.
type Status string

// Defined statuses.
const (
	// Stable indicates that the rule didn't produce any obvious false positives
	// in multiple environments over a long period of time.
	Stable Status = "stable"
	// Test indicates that the rule doesn't show any obvious false positives
	// on a limited set of test systems.
	Test Status = "test"
	// Experimental indicates a new rule that hasn't been tested outside of lab environments
	// and could lead to many false positives.
	Experimental Status = "experimental"
	// Deprecated indicates the rule is to replace or cover another one.
	// The link between both rules is made via the related field.
	Deprecated Status = "deprecated"
	// Unsupported indicates the rule can not be used in its current state
	// (special correlation log, home-made fields, etc.).
	Unsupported Status = "unsupported"
)

// IsKnown reports whether the status string matches one of the known constants.
func (status Status) IsKnown() bool {
	return status == Stable ||
		status == Test ||
		status == Experimental ||
		status == Deprecated ||
		status == Unsupported
}

// Level is an enumeration of the criticalities of a triggered [Rule].
type Level string

// Defined levels.
const (
	// Informational indicates a rule is intended for enrichment of events,
	// e.g. by tagging them.
	// No case or alerting should be triggered by such rules
	// because it is expected that a huge amount of events will match these rules.
	Informational Level = "informational"
	// Low indicates that a rule is a notable event but rarely an incident.
	// Low rated events can be relevant in high numbers or combination with others.
	// Immediate reaction shouldn't be necessary, but a regular review is recommended.
	Low Level = "low"
	// Medium indicates that a rule is a relevant event that should be reviewed manually
	// on a more frequent basis.
	Medium Level = "medium"
	// High indicates that a rule is a relevant event that should trigger an internal alert
	// and requires a prompt review.
	High Level = "high"
	// Critical indicates that a rule is a highly relevant event that indicates an incident.
	// Critical events should be reviewed immediately.
	// It is used only for cases in which probability borders certainty.
	Critical Level = "critical"
)

// IsKnown reports whether the level string matches one of the known constants.
func (level Level) IsKnown() bool {
	return level == Informational ||
		level == Low ||
		level == Medium ||
		level == High ||
		level == Critical
}

// Relation is a reference to another related rule.
type Relation struct {
	ID   string
	Type RelationType
}

// RelationType is an enumeration of relation types.
type RelationType string

// Defined relation types.
const (
	// Derived signals the rule was derived from the referred rule or rules,
	// which may remain active.
	Derived RelationType = "derived"
	// Obsoletes signals the rule obsoletes the referred rule or rules,
	// which aren't used anymore.
	Obsoletes RelationType = "obsoletes"
	// Merged signals the rule was merged from the referred rules.
	// The rules may be still existing and in use.
	Merged RelationType = "merged"
	// Renamed signals the rule had previously the referred identifier or identifiers
	// but was renamed for whatever reason,
	// e.g. from a private naming scheme to UUIDs, to resolve collisions etc.
	// It's not expected that a rule with this id exists anymore.
	Renamed RelationType = "renamed"
	// Similar is used to relate similar rules to each other
	// (e.g. same detection content applied to different log sources,
	// rule that is a modified version of another rule with a different level).
	Similar RelationType = "similar"
)

// IsKnown reports whether the relation type string matches one of the known constants.
func (typ RelationType) IsKnown() bool {
	return typ == Derived ||
		typ == Obsoletes ||
		typ == Merged ||
		typ == Renamed ||
		typ == Similar
}
