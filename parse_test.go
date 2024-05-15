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
					Expr: &NamedExpr{
						Name: "selection",
						X: &SearchAtom{
							Field:    "Image",
							Patterns: []string{`C:\Windows\System32\whoami.exe`},
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
					Expr: &NamedExpr{
						Name: "selection_source",
						X: &AndExpr{
							X: []Expr{
								&SearchAtom{
									Field:    "eventSource",
									Patterns: []string{"cloudtrail.amazonaws.com"},
								},
								&SearchAtom{
									Field: "eventName",
									Patterns: []string{
										"StopLogging",
										"UpdateTrail",
										"DeleteTrail",
									},
								},
							},
						},
					},
				},
				FalsePositives: []string{
					"Valid change in a Trail",
				},
				Level: Medium,
			},
		},
		{
			filename: "lnx_buffer_overflows.yml",
			want: &Rule{
				Title:       "Buffer Overflow Attempts",
				ID:          "18b042f0-2ecd-4b6e-9f8d-aa7a7e7de781",
				Status:      Stable,
				Description: "Detects buffer overflow attempts in Unix system log files",
				References: []string{
					"https://github.com/ossec/ossec-hids/blob/1ecffb1b884607cb12e619f9ab3c04f530801083/etc/rules/attack_rules.xml",
				},
				Author: "Florian Roth (Nextron Systems)",
				Date:   NewDate(2017, time.March, 1),
				Tags: []string{
					"attack.t1068",
					"attack.privilege_escalation",
				},
				LogSource: &LogSource{
					Product: "linux",
				},
				Detection: &Detection{
					Expr: &NamedExpr{
						Name: "keywords",
						X: &SearchAtom{
							Patterns: []string{
								`attempt to execute code on stack by`,
								`FTP LOGIN FROM .* 0bin0sh`,
								`rpc.statd[\d+]: gethostbyname error for`,
								`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
							},
						},
					},
				},
				FalsePositives: []string{
					"Unknown",
				},
				Level: High,
			},
		},
		{
			filename: "mixed_detection.yml",
			want: &Rule{
				Title:       "Mixed Detection List Example",
				Description: "A contrived example for mixing lists of string matches with field matches",
				LogSource: &LogSource{
					Product: "windows",
				},
				Detection: &Detection{
					Expr: &NamedExpr{
						Name: "selection",
						X: &OrExpr{
							[]Expr{
								&SearchAtom{
									Patterns: []string{"EVILSERVICE"},
								},
								&SearchAtom{
									Field:     "Image",
									Modifiers: []string{"endswith"},
									Patterns:  []string{`\\example.exe`},
								},
							},
						},
					},
				},
			},
		},
		{
			filename: "proxy_ua_susp_base64.yml",
			want: &Rule{
				Title: "Potential Base64 Encoded User-Agent",
				ID:    "894a8613-cf12-48b3-8e57-9085f54aa0c3",
				Related: []Relation{
					{
						ID:   "d443095b-a221-4957-a2c4-cd1756c9b747",
						Type: Derived,
					},
				},
				Status:      Test,
				Description: "Detects User Agent strings that end with an equal sign, which can be a sign of base64 encoding.",
				References: []string{
					"https://blogs.jpcert.or.jp/en/2022/07/yamabot.html",
					"https://deviceatlas.com/blog/list-of-user-agent-strings#desktop",
				},
				Author:   "Florian Roth (Nextron Systems), Brian Ingram (update)",
				Date:     NewDate(2022, time.July, 8),
				Modified: NewDate(2023, time.May, 4),
				Tags: []string{
					"attack.command_and_control",
					"attack.t1071.001",
				},
				LogSource: &LogSource{
					Category: "proxy",
				},
				Detection: &Detection{
					Expr: &NamedExpr{
						Name: "selection",
						X: &SearchAtom{
							Field:     "c-useragent",
							Modifiers: []string{"endswith"},
							Patterns:  []string{"="},
						},
					},
				},
				FalsePositives: []string{"Unknown"},
				Level:          Medium,
			},
		},
		{
			filename: "lnx_cron_crontab_file_modification.yml",
			want: &Rule{
				Title:       "Modifying Crontab",
				ID:          "af202fd3-7bff-4212-a25a-fb34606cfcbe",
				Status:      Test,
				Description: "Detects suspicious modification of crontab file.",
				References: []string{
					"https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.003/T1053.003.md",
				},
				Author: "Pawel Mazur",
				Date:   NewDate(2022, time.April, 16),
				Tags: []string{
					"attack.persistence",
					"attack.t1053.003",
				},
				LogSource: &LogSource{
					Product: "linux",
					Service: "cron",
				},
				Detection: &Detection{
					Expr: &NamedExpr{
						Name: "keywords",
						X: &SearchAtom{
							Patterns: []string{"REPLACE"},
						},
					},
				},
				FalsePositives: []string{
					"Legitimate modification of crontab",
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
