// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigmalite

import (
	"encoding/base64"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gopkg.in/yaml.v3"
)

func TestParseRule(t *testing.T) {
	tests := []struct {
		filename string
		want     *Rule
	}{
		{
			filename: "sigma/whoami.yml",
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
			filename: "sigma/aws_cloudtrail_disable_logging.yml",
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
			filename: "sigma/lnx_buffer_overflows.yml",
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
			filename: "sigma/proxy_ua_susp_base64.yml",
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
			filename: "sigma/lnx_cron_crontab_file_modification.yml",
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
		{
			filename: "sigma/lnx_auditd_coinminer.yml",
			want: &Rule{
				Title:       "Possible Coin Miner CPU Priority Param",
				ID:          "071d5e5a-9cef-47ec-bc4e-a42e34d8d0ed",
				Status:      Test,
				Description: "Detects command line parameter very often used with coin miners",
				References: []string{
					"https://xmrig.com/docs/miner/command-line-options",
				},
				Author:   "Florian Roth (Nextron Systems)",
				Date:     NewDate(2021, time.October, 9),
				Modified: NewDate(2022, time.December, 25),
				Tags: []string{
					"attack.privilege_escalation",
					"attack.t1068",
				},
				LogSource: &LogSource{
					Product: "linux",
					Service: "auditd",
				},
				Detection: &Detection{
					Expr: &OrExpr{
						X: []Expr{
							&NamedExpr{
								Name: "cmd1",
								X: &SearchAtom{
									Field:     "a1",
									Modifiers: []string{"startswith"},
									Patterns:  []string{"--cpu-priority"},
								},
							},
							&NamedExpr{
								Name: "cmd2",
								X: &SearchAtom{
									Field:     "a2",
									Modifiers: []string{"startswith"},
									Patterns:  []string{"--cpu-priority"},
								},
							},
							&NamedExpr{
								Name: "cmd3",
								X: &SearchAtom{
									Field:     "a3",
									Modifiers: []string{"startswith"},
									Patterns:  []string{"--cpu-priority"},
								},
							},
							&NamedExpr{
								Name: "cmd4",
								X: &SearchAtom{
									Field:     "a4",
									Modifiers: []string{"startswith"},
									Patterns:  []string{"--cpu-priority"},
								},
							},
							&NamedExpr{
								Name: "cmd5",
								X: &SearchAtom{
									Field:     "a5",
									Modifiers: []string{"startswith"},
									Patterns:  []string{"--cpu-priority"},
								},
							},
							&NamedExpr{
								Name: "cmd6",
								X: &SearchAtom{
									Field:     "a6",
									Modifiers: []string{"startswith"},
									Patterns:  []string{"--cpu-priority"},
								},
							},
							&NamedExpr{
								Name: "cmd7",
								X: &SearchAtom{
									Field:     "a7",
									Modifiers: []string{"startswith"},
									Patterns:  []string{"--cpu-priority"},
								},
							},
						},
					},
				},
				FalsePositives: []string{
					"Other tools that use a --cpu-priority flag",
				},
				Level: Critical,
			},
		},
		{
			filename: "sigma/file_access_win_browser_credential_access.yml",
			want: &Rule{
				Title:  "Access To Browser Credential Files By Uncommon Application",
				ID:     "91cb43db-302a-47e3-b3c8-7ede481e27bf",
				Status: Experimental,
				Description: "Detects file access requests to browser credential stores by uncommon processes.\n" +
					"Could indicate potential attempt of credential stealing.\n" +
					"Requires heavy baselining before usage\n",
				References: []string{
					"https://www.zscaler.com/blogs/security-research/ffdroider-stealer-targeting-social-media-platform-users",
					"https://github.com/lclevy/firepwd",
				},
				Author:   "frack113",
				Date:     NewDate(2022, time.April, 9),
				Modified: NewDate(2023, time.December, 18),
				Tags: []string{
					"attack.t1003",
					"attack.credential_access",
				},
				LogSource: &LogSource{
					Category:   "file_access",
					Product:    "windows",
					Definition: "Requirements: Microsoft-Windows-Kernel-File ETW provider",
				},
				Detection: &Detection{
					Expr: &AndExpr{
						X: []Expr{
							&OrExpr{
								X: []Expr{
									&NamedExpr{
										Name: "selection_chromium",
										X: &SearchAtom{
											Field:     "FileName",
											Modifiers: []string{"contains"},
											Patterns: []string{
												`\Appdata\Local\Chrome\User Data\Default\Login Data`,
												`\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`,
												`\AppData\Local\Google\Chrome\User Data\Local State`,
											},
										},
									},
									&NamedExpr{
										Name: "selection_firefox",
										X: &SearchAtom{
											Field:     "FileName",
											Modifiers: []string{"endswith"},
											Patterns: []string{
												`\cookies.sqlite`,
												`release\key3.db`,
												`release\key4.db`,
												`release\logins.json`,
											},
										},
									},
									&NamedExpr{
										Name: "selection_ie",
										X: &SearchAtom{
											Field:     "FileName",
											Modifiers: []string{"endswith"},
											Patterns:  []string{`\Appdata\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`},
										},
									},
								},
							},
							&NotExpr{X: &OrExpr{
								X: []Expr{
									&NamedExpr{
										Name: "filter_main_generic",
										X: &SearchAtom{
											Field:     "Image",
											Modifiers: []string{"contains"},
											Patterns: []string{
												`:\Program Files (x86)\`,
												`:\Program Files\`,
												`:\Windows\system32\`,
												`:\Windows\SysWOW64\`,
											},
										},
									},
									&NamedExpr{
										Name: "filter_main_system",
										X: &SearchAtom{
											Field:    "Image",
											Patterns: []string{"System"},
										},
									},
								},
							}},
							&NotExpr{X: &OrExpr{
								X: []Expr{
									&NamedExpr{
										Name: "filter_optional_defender",
										X: &AndExpr{
											X: []Expr{
												&SearchAtom{
													Field:     "Image",
													Modifiers: []string{"contains"},
													Patterns: []string{
														`:\ProgramData\Microsoft\Windows Defender\`,
													},
												},
												&SearchAtom{
													Field:     "Image",
													Modifiers: []string{"endswith"},
													Patterns: []string{
														`\MpCopyAccelerator.exe`,
														`\MsMpEng.exe`,
													},
												},
											},
										},
									},
									&NamedExpr{
										Name: "filter_optional_thor",
										X: &SearchAtom{
											Field:     "Image",
											Modifiers: []string{"endswith"},
											Patterns: []string{
												`\thor64.exe`,
												`\thor.exe`,
											},
										},
									},
								},
							}},
						},
					},
				},
				FalsePositives: []string{
					`Antivirus, Anti-Spyware, Anti-Malware Software`,
					`Backup software`,
					`Legitimate software installed on partitions other than "C:\"`,
					`Searching software such as "everything.exe"`,
				},
				Level: Medium,
			},
		},
		{
			filename: "condition_list.yml",
			want: &Rule{
				Title:       "Condition List Example",
				Description: "A contrived example for using a list of conditions.",
				LogSource: &LogSource{
					Product: "windows",
				},
				Detection: &Detection{
					Expr: &OrExpr{
						X: []Expr{
							&NamedExpr{
								Name: "selection1",
								X: &SearchAtom{
									Field:     "Image",
									Modifiers: []string{"endswith"},
									Patterns:  []string{`\\example.exe`},
								},
							},
							&NamedExpr{
								Name: "selection2",
								X: &SearchAtom{
									Field:     "Image",
									Modifiers: []string{"endswith"},
									Patterns:  []string{`\\evil.exe`},
								},
							},
						},
					},
				},
			},
		},
		{
			filename: "sigma/lnx_auditd_unix_shell_configuration_modification.yml",
			want: &Rule{
				Title: "Unix Shell Configuration Modification",
				ID:    "a94cdd87-6c54-4678-a6cc-2814ffe5a13d",
				Related: []Relation{
					{
						ID:   "e74e15cc-c4b6-4c80-b7eb-dfe49feb7fe9",
						Type: Obsoletes,
					},
				},
				Status:      Test,
				Description: "Detect unix shell configuration modification. Adversaries may establish persistence through executing malicious commands triggered when a new shell is opened.",
				References: []string{
					"https://objective-see.org/blog/blog_0x68.html",
					"https://www.glitch-cat.com/p/green-lambert-and-attack",
					"https://www.anomali.com/blog/pulling-linux-rabbit-rabbot-malware-out-of-a-hat",
				},
				Author:   "Peter Matkovski, IAI",
				Date:     NewDate(2023, time.March, 6),
				Modified: NewDate(2023, time.March, 15),
				Tags: []string{
					"attack.persistence",
					"attack.t1546.004",
				},
				LogSource: &LogSource{
					Product: "linux",
					Service: "auditd",
				},
				Detection: &Detection{
					Expr: &NamedExpr{
						Name: "selection",
						X: &AndExpr{
							X: []Expr{
								&SearchAtom{
									Field:    "type",
									Patterns: []string{"PATH"},
								},
								&SearchAtom{
									Field: "name",
									Patterns: []string{
										"/etc/shells",
										"/etc/profile",
										"/etc/profile.d/*",
										"/etc/bash.bashrc",
										"/etc/bashrc",
										"/etc/zsh/zprofile",
										"/etc/zsh/zshrc",
										"/etc/zsh/zlogin",
										"/etc/zsh/zlogout",
										"/etc/csh.cshrc",
										"/etc/csh.login",
										"/root/.bashrc",
										"/root/.bash_profile",
										"/root/.profile",
										"/root/.zshrc",
										"/root/.zprofile",
										"/home/*/.bashrc",
										"/home/*/.zshrc",
										"/home/*/.bash_profile",
										"/home/*/.zprofile",
										"/home/*/.profile",
										"/home/*/.bash_login",
										"/home/*/.bash_logout",
										"/home/*/.zlogin",
										"/home/*/.zlogout",
									},
								},
							},
						},
					},
				},
				FalsePositives: []string{
					"Admin or User activity are expected to generate some false positives",
				},
				Level: Medium,
			},
		},
		{
			filename: "sigma/win_system_susp_service_installation_script.yml",
			want: &Rule{
				Title:       "Suspicious Service Installation Script",
				ID:          "70f00d10-60b2-4f34-b9a0-dc3df3fe762a",
				Status:      Test,
				Description: "Detects suspicious service installation scripts",
				References:  []string{"Internal Research"},
				Author:      "pH-T (Nextron Systems)",
				Date:        NewDate(2022, time.March, 18),
				Modified:    NewDate(2024, time.March, 5),
				Tags: []string{
					"attack.persistence",
					"attack.privilege_escalation",
					"car.2013-09-005",
					"attack.t1543.003",
				},
				LogSource: &LogSource{
					Product: "windows",
					Service: "system",
				},
				Detection: &Detection{
					Expr: &AndExpr{
						X: []Expr{
							&NamedExpr{
								Name: "selection_binaries",
								X: &SearchAtom{
									Field:     "ImagePath",
									Modifiers: []string{"contains"},
									Patterns: []string{
										"cscript",
										"mshta",
										"powershell",
										"pwsh",
										"regsvr32",
										"rundll32",
										"wscript",
									},
								},
							},
							&NamedExpr{
								Name: "selection_cmd_flags",
								X: &SearchAtom{
									Field:     "ImagePath",
									Modifiers: []string{"contains", "windash"},
									Patterns: []string{
										" -c ",
										" -r ",
										" -k ",
									},
								},
							},
							&NamedExpr{
								Name: "selection_eid",
								X: &AndExpr{
									X: []Expr{
										&SearchAtom{
											Field:    "Provider_Name",
											Patterns: []string{"Service Control Manager"},
										},
										&SearchAtom{
											Field:    "EventID",
											Patterns: []string{"7045"},
										},
									},
								},
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
			filename: "sigma/win_security_admin_logon.yml",
			want: &Rule{
				Title:       "User with Privileges Logon",
				ID:          "94309181-d345-4cbf-b5fe-061769bdf9cb",
				Status:      Test,
				Description: `Detects logon with "Special groups" and "Special Privileges" can be thought of as Administrator groups or privileges.`,
				References: []string{
					"https://github.com/Yamato-Security/EnableWindowsLogSettings/blob/7f6d755d45ac7cc9fc35b0cbf498e6aa4ef19def/ConfiguringSecurityLogAuditPolicies.md",
					"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672",
					"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4964",
				},
				Author:   "frack113",
				Date:     NewDate(2022, time.October, 14),
				Modified: NewDate(2023, time.December, 14),
				Tags: []string{
					"attack.defense_evasion",
					"attack.lateral_movement",
					"attack.credential_access",
					"attack.t1558",
					"attack.t1649",
					"attack.t1550",
				},
				LogSource: &LogSource{
					Service: "security",
					Product: "windows",
				},
				Detection: &Detection{
					Expr: &AndExpr{
						X: []Expr{
							&NamedExpr{
								Name: "selection",
								X: &SearchAtom{
									Field: "EventID",
									Patterns: []string{
										"4672",
										"4964",
									},
								},
							},
							&NotExpr{
								X: &OrExpr{
									X: []Expr{
										&NamedExpr{
											Name: "filter_main_local_system",
											X: &SearchAtom{
												Field:    "SubjectUserSid",
												Patterns: []string{"S-1-5-18"},
											},
										},
										&NamedExpr{
											Name: "filter_main_valid_account",
											X: &SearchAtom{
												Field:     "SubjectUserName",
												Modifiers: []string{"expand"},
												Patterns:  []string{"%Admins_Workstations%"},
											},
										},
									},
								},
							},
						},
					},
				},
				FalsePositives: []string{"Unknown"},
				Level:          Low,
			},
		},
		{
			filename: "extra.yml",
			want: &Rule{
				Title:       "Metadata example",
				Description: "Contains an extra top-level field",
				LogSource: &LogSource{
					Product: "windows",
				},
				Detection: &Detection{
					Expr: &NamedExpr{
						Name: "selection",
						X: &SearchAtom{
							Patterns: []string{"hello"},
						},
					},
				},
				Extra: map[string]Decoder{
					"extrametadata": &yaml.Node{
						Kind:   yaml.ScalarNode,
						Tag:    "!!str",
						Value:  "foo",
						Line:   9,
						Column: 16,
					},
				},
			},
		},
		{
			filename: "sigma/sysmon_wmi_susp_encoded_scripts.yml",
			want: &Rule{
				ID:          "83844185-1c5b-45bc-bcf3-b5bf3084ca5b",
				Title:       "Suspicious Encoded Scripts in a WMI Consumer",
				Description: "Detects suspicious encoded payloads in WMI Event Consumers",
				References: []string{
					"https://github.com/RiccardoAncarani/LiquidSnake",
				},
				Author:   "Florian Roth (Nextron Systems)",
				Status:   "test",
				Date:     NewDate(2021, time.September, 01),
				Modified: NewDate(2022, time.October, 9),
				LogSource: &LogSource{
					Category: "wmi_event",
					Product:  "windows",
				},
				Fields:         []string{"User", "Operation"},
				FalsePositives: []string{"Unknown"},
				Tags: []string{
					"attack.execution",
					"attack.t1047",
					"attack.persistence",
					"attack.t1546.003",
				},
				Detection: &Detection{
					Expr: &NamedExpr{
						Name: "selection_destination",
						X: &SearchAtom{
							Field:     "Destination",
							Modifiers: []string{"base64offset", "contains"},
							Patterns: []string{
								`WriteProcessMemory`,
								`This program cannot be run in DOS mode`,
								`This program must be run under Win32`,
							},
						},
					},
				},
				Level: High,
			},
		},
	}

	for _, test := range tests {
		t.Run(path.Base(test.filename), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(test.filename)))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseRule(data)
			if err != nil {
				t.Fatal(err)
			}
			compareAtoms := cmpopts.IgnoreUnexported(SearchAtom{})

			// Maintain an explicit allow-list of fields in yaml.Node that we want to compare.
			// This keeps us from being brittle to upgrades to the yaml package.
			compareYAMLNodes := cmp.FilterPath(func(p cmp.Path) bool {
				if p.Index(-2).Type() != yamlNodeType {
					return false
				}
				field := p.Last().(cmp.StructField).Name()
				return field != "Kind" &&
					field != "Tag" &&
					field != "Value" &&
					field != "Content" &&
					field != "Line" &&
					field != "Column"
			}, cmp.Ignore())

			if diff := cmp.Diff(test.want, got, compareAtoms, compareYAMLNodes); diff != "" {
				t.Errorf("ParseRule(...) (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBase64Permuter(t *testing.T) {
	var ogstring = "foobar"
	for j := 0; j < 3; j++ {
		var pstring = ogstring
		perms := base64permute(pstring)
		for i := 0; i < 20; i++ {
			pbs := base64.RawStdEncoding.EncodeToString([]byte(pstring))
			var has bool = false
			for _, p := range perms {
				if strings.Contains(pbs, p) {
					has = true
					break
				}
			}
			if !has {
				t.Errorf("Permutation not found: %s", pbs)
			}
			pstring = "a" + pstring
		}
		ogstring = "a" + ogstring
	}
}

var yamlNodeType = reflect.TypeOf((*yaml.Node)(nil)).Elem()

func TestWindashpermute(t *testing.T) {
	tests := []struct {
		pattern  string
		expected []string
	}{
		{
			pattern: "-test",
			expected: []string{
				"-test",
				"/test",
				fmt.Sprintf("%stest", EnDash),
				fmt.Sprintf("%stest", EmDash),
				fmt.Sprintf("%stest", HorizontalBar),
			},
		},
		{
			pattern: "/test",
			expected: []string{
				"-test",
				"/test",
				fmt.Sprintf("%stest", EnDash),
				fmt.Sprintf("%stest", EmDash),
				fmt.Sprintf("%stest", HorizontalBar),
			},
		},
		{
			pattern: "-test-boundaries",
			expected: []string{
				"-test-boundaries",
				"/test-boundaries",
				fmt.Sprintf("%stest-boundaries", EnDash),
				fmt.Sprintf("%stest-boundaries", EmDash),
				fmt.Sprintf("%stest-boundaries", HorizontalBar),
			},
		},
	}

	for _, test := range tests {
		got := windashpermute(test.pattern)
		slices.Sort(got)
		slices.Sort(test.expected)
		if !slices.Equal(got, test.expected) {
			t.Errorf("Expected %v, got %v", test.expected, got)
		}
	}
}
