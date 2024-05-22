// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigma

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectionMatches(t *testing.T) {
	tests := []struct {
		filename string
		entry    *LogEntry
		want     bool
	}{
		{
			filename: "sigma/aws_cloudtrail_disable_logging.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"eventSource": "cloudtrail.amazonaws.com",
					"eventName":   "StopLogging",
				},
			},
			want: true,
		},
		{
			filename: "sigma/aws_cloudtrail_disable_logging.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"eventSource": "cloudtrail.amazonaws.com",
					"eventName":   "StartLogging",
				},
			},
			want: false,
		},
		{
			filename: "sigma/aws_cloudtrail_disable_logging.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"eventSource": "example.com",
					"eventName":   "StopLogging",
				},
			},
			want: false,
		},
		{
			filename: "sigma/aws_cloudtrail_disable_logging.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"eventSource": "cloudtrail.amazonaws.com",
					"eventName":   "StopLoggingOrElse",
				},
			},
			want: false,
		},
		{
			filename: "sigma/lnx_buffer_overflows.yml",
			entry: &LogEntry{
				Message: "hello world",
			},
			want: false,
		},
		{
			filename: "sigma/lnx_buffer_overflows.yml",
			entry: &LogEntry{
				Message: "there was an attempt to execute code on stack by main",
			},
			want: true,
		},
		{
			filename: "sigma/lnx_buffer_overflows.yml",
			entry: &LogEntry{
				Message: "THERE WAS AN ATTEMPT TO EXECUTE CODE ON STACK BY MAIN",
			},
			want: true,
		},
		{
			filename: "sigma/whoami.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"Image": `C:\Windows\System32\whoami.exe`,
				},
			},
			want: true,
		},
		{
			filename: "sigma/whoami.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"Image": "foo",
				},
			},
			want: false,
		},
		{
			filename: "sigma/lnx_auditd_unix_shell_configuration_modification.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"type": "PATH",
					"name": "/etc/shells",
				},
			},
			want: true,
		},
		{
			filename: "sigma/lnx_auditd_unix_shell_configuration_modification.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"type": "PATH",
					"name": "/etc/profile.d/01-locale-fix.sh",
				},
			},
			want: true,
		},
		{
			filename: "sigma/lnx_auditd_unix_shell_configuration_modification.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"type": "PATH",
					"name": "/home/light/.zshrc",
				},
			},
			want: true,
		},
		{
			filename: "sigma/lnx_auditd_unix_shell_configuration_modification.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"type": "PATH",
					"name": "/var/lib/foo.tmp",
				},
			},
			want: false,
		},
		{
			filename: "sigma/lnx_auditd_coinminer.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"comm": "echo",
					"a1":   "hello",
				},
			},
			want: false,
		},
		{
			filename: "sigma/lnx_auditd_coinminer.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"comm": "echo",
					"a1":   "--cpu-priority=10",
					"a2":   "hello",
				},
			},
			want: true,
		},
		{
			filename: "sigma/proxy_ua_susp_base64.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"c-useragent": "lynx version=1.0",
				},
			},
			want: false,
		},
		{
			filename: "sigma/proxy_ua_susp_base64.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"c-useragent": "based==",
				},
			},
			want: true,
		},
		{
			filename: "sigma/file_access_win_browser_credential_access.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"Image":    "example.exe",
					"FileName": `C:\foo.txt`,
				},
			},
			want: false,
		},
		{
			filename: "sigma/file_access_win_browser_credential_access.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"Image":    "example.exe",
					"FileName": `C:\Users\light\AppData\Local\Chrome\User Data\Default\Login Data`,
				},
			},
			want: true,
		},
		{
			filename: "sigma/file_access_win_browser_credential_access.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"Image":    "System",
					"FileName": `C:\Users\light\AppData\Local\Chrome\User Data\Default\Login Data`,
				},
			},
			want: false,
		},
		{
			filename: "sigma/win_system_susp_service_installation_script.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"Provider_Name": "Service Control Manager",
					"EventID":       "7045",
					"ImagePath":     "powershell -c foo",
				},
			},
			want: true,
		},
		{
			filename: "sigma/win_system_susp_service_installation_script.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"Provider_Name": "Service Control Manager",
					"EventID":       "7045",
					"ImagePath":     "powershell /c foo",
				},
			},
			want: true,
		},
		{
			filename: "sigma/win_system_susp_service_installation_script.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"Provider_Name": "Service Control Manager",
					"EventID":       "7045",
					"ImagePath":     "powershell foo",
				},
			},
			want: false,
		},
	}

	for _, test := range tests {
		data, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(test.filename)))
		if err != nil {
			t.Error(err)
			continue
		}
		rule, err := ParseRule(data)
		if err != nil {
			t.Errorf("%s: %v", test.filename, err)
			continue
		}
		got := rule.Detection.Matches(test.entry)
		if got != test.want {
			t.Errorf("ParseRule(%q).Detection.Matches(%+v) = %t; want %t", test.filename, test.entry, got, test.want)
		}
	}
}
