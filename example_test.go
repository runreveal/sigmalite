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

// ExampleResolver demonstrates custom field resolution
type ExampleResolver struct{}

func (r *ExampleResolver) Resolve(fieldName string, entry *sigma.LogEntry) []string {
	switch fieldName {
	case "process.users":
		// This could query nested JSON, arrays, wildcards, etc.
		// For this example, we'll simulate extracting users from different fields
		var users []string
		if user, ok := entry.Fields["Event.Process.User"]; ok {
			users = append(users, user)
		}
		if user, ok := entry.Fields["Event.Login.User"]; ok {
			users = append(users, user)
		}
		if user, ok := entry.Fields["Event.Session.User"]; ok {
			users = append(users, user)
		}
		return users
	default:
		return nil
	}
}

func Example_fieldResolver() {
	// Example demonstrating custom field resolution
	rule, err := sigma.ParseRule([]byte(`
title: Field Resolver Example
detection:
  selection:
    process.users: "administrator"
  condition: selection
`))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	resolver := &ExampleResolver{}
	opts := &sigma.MatchOptions{
		FieldResolver: resolver,
	}

	// This entry will match because the resolver finds "administrator" in Event.Process.User
	entry1 := &sigma.LogEntry{
		Fields: map[string]string{
			"Event.Process.User": "administrator",
			"Event.Process.Name": "cmd.exe",
		},
	}

	// This entry will also match because the resolver finds "administrator" in Event.Session.User
	entry2 := &sigma.LogEntry{
		Fields: map[string]string{
			"Event.Session.User": "administrator",
			"Event.Session.Type": "Remote",
		},
	}

	// This entry won't match because no user field contains "administrator"
	entry3 := &sigma.LogEntry{
		Fields: map[string]string{
			"Event.Process.User": "regular_user",
			"Event.Login.User":   "guest_user",
		},
	}

	fmt.Println("Rule:", rule.Title)
	fmt.Println("Entry 1 matches?", rule.Detection.Matches(entry1, opts))
	fmt.Println("Entry 2 matches?", rule.Detection.Matches(entry2, opts))
	fmt.Println("Entry 3 matches?", rule.Detection.Matches(entry3, opts))
	// Output:
	// Rule: Field Resolver Example
	// Entry 1 matches? true
	// Entry 2 matches? true
	// Entry 3 matches? false
}
