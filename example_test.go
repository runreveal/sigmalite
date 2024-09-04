// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigma_test

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
