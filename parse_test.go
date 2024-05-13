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
			filename: "whoami.yml",
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
		{
			filename: "aws_cloudtrail_disable_logging.yml",
			want: &Rule{
				Title:       "AWS CloudTrail Important Change",
				ID:          "4db60cc0-36fb-42b7-9b58-a5b53019fb74",
				Status:      Test,
				Description: "Detects disabling, deleting and updating of a Trail",
				References: []string{
					"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html",
				},
				Author:   "vitaliy0x1",
				Date:     NewDate(2020, time.January, 21),
				Modified: NewDate(2022, time.October, 9),
				Tags: []string{
					"attack.defense_evasion",
					"attack.t1562.001",
				},
				LogSource: &LogSource{
					Product: "aws",
					Service: "cloudtrail",
				},
				Detection: &Detection{
					Condition: "selection_source",
					Identifiers: map[string]*SearchIdentifier{
						"selection_source": {},
					},
				},
				FalsePositives: []string{
					"Valid change in a Trail",
				},
				Level: Medium,
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
