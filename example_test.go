// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigmalite_test

import (
	"fmt"

	sigma "github.com/runreveal/sigmalite"
)

func Example() {
	rule, err := sigma.ParseRule([]byte(`
title: My example rule
detection:
  keywords:
    - foo
    - bar
  selection:
    EventId: 1234
  condition: keywords and selection
`))
	if err != nil {
		// Handle error...
	}
	entry := &sigma.LogEntry{
		Message: "Hello foo",
		Fields: map[string]string{
			"EventId": "1234",
		},
	}
	isMatch := rule.Detection.Matches(entry, nil)
	fmt.Println("Rule:", rule.Title)
	fmt.Println("Matches?", isMatch)
	// Output:
	// Rule: My example rule
	// Matches? true
}

func ExampleRule_EvaluateRiskScore() {
	rule, err := sigma.ParseRule([]byte(`
title: Critical Process Execution
level: high
detection:
  selection1:
    EventId: 4688
    ProcessName: critical.exe
  selection2:
    EventId: 4688
    ProcessName: important.exe
  condition: selection1 or selection2
risk_score:
  default: 50
  scores:
    selection1: 90
    selection2: 70
`))
	if err != nil {
		// Handle error...
		return
	}

	// Create a log entry
	entry := &sigma.LogEntry{
		Fields: map[string]string{
			"EventId":     "4688",
			"ProcessName": "critical.exe",
		},
	}

	result := rule.EvaluateRiskScore(entry, nil)

	fmt.Println("Rule matched:", result.Matched)
	fmt.Printf("Matching expression:%s\n", result.Expression)
	fmt.Println("Risk score:", result.Score)

	// Default scoring based on rule's level
	fmt.Println("Default risk score (from 'high' level):", 75)

	// Output:
	// Rule matched: true
	// Matching expression:selection1
	// Risk score: 90
	// Default risk score (from 'high' level): 75
}
