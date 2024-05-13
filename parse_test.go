// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigma

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestParseRule(t *testing.T) {
	tests := []struct {
		filename string
		want     *Rule
	}{
		{
			filename: "whoami.yaml",
			want: &Rule{
				Title:       "Whoami Execution",
				Description: "Detects a whoami.exe execution",
				References: []string{
					"https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment",
				},
				Author: "Florian Roth",
				Date:   NewDate(2019, time.October, 23),
				LogSource: &LogSource{
					Category: "process_creation",
					Product:  "windows",
				},
				Detection: &Detection{
					Condition: "selection",
					Identifiers: map[string]*SearchIdentifier{
						"selection": {
							// TODO(soon)
						},
					},
				},
				Level: High,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.filename, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(test.filename)))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseRule(data)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("ParseRule(...) (-want +got):\n%s", diff)
			}
		})
	}
}
