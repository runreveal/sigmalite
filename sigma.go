// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

// Package sigma provides a parser and an execution engine
// for the [Sigma detection format].
//
// [Sigma detection format]: https://sigmahq.io/
package sigma

// Rule represents a parsed Sigma rule file.
type Rule struct {
	Title       string
	ID          string
	Description string
	LogSource   *LogSource
	Detection   *Detection
}

// LogSource describes the log data on which a [Detection] is meant to be applied to.
type LogSource struct {
	Category   string
	Product    string
	Service    string
	Definition string
}

// Detection describes the pattern that a [Rule] is searching for.
type Detection struct {
	Condition   string
	Identifiers map[string]*SearchIdentifier
}

// SearchIdentifier is a boolean condition that can be used as a term
// in the condition of a [Detection].
type SearchIdentifier struct {
	// TODO(soon)
}
