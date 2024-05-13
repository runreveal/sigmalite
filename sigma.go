// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

// Package sigma provides a parser and an execution engine
// for the [Sigma detection format].
//
// [Sigma detection format]: https://sigmahq.io/
package sigma

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
}

// LogSource describes the log data on which a [Detection] is meant to be applied to.
type LogSource struct {
	Category   string
	Product    string
	Service    string
	Definition string
}

// Detection describes the pattern that a [Rule] is matching on.
type Detection struct {
	Condition   string
	Identifiers map[string]*SearchIdentifier
}

// SearchIdentifier is a boolean condition that can be used as a term
// in the condition of a [Detection].
type SearchIdentifier struct {
	// TODO(soon)
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
