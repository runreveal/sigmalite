// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigmalite

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectionMatches(t *testing.T) {
	tests := []struct {
		filename string
		entry    *LogEntry
		options  *MatchOptions
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
			filename: "sigma/aws_cloudtrail_disable_logging_caseinsensitive.yml",
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
		{
			filename: "sigma/win_security_admin_logon.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"EventID":         "4672",
					"SubjectUserSid":  "S-1-5-18",
					"SubjectUserName": "AdminMachine",
				},
			},
			options: &MatchOptions{
				Placeholders: map[string][]string{
					"Admins_Workstations": {"OtherAdminMachine", "AdminMachine"},
				},
			},
			want: false,
		},
		{
			filename: "sigma/win_security_admin_logon.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"EventID":         "4672",
					"SubjectUserSid":  "S-1-2-3",
					"SubjectUserName": "AdminMachine",
				},
			},
			options: &MatchOptions{
				Placeholders: map[string][]string{
					"Admins_Workstations": {"OtherAdminMachine", "AdminMachine"},
				},
			},
			want: false,
		},
		{
			filename: "sigma/win_security_admin_logon.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"EventID":         "4672",
					"SubjectUserSid":  "S-1-2-3",
					"SubjectUserName": "UserMachine",
				},
			},
			options: &MatchOptions{
				Placeholders: map[string][]string{
					"Admins_Workstations": {"OtherAdminMachine", "AdminMachine"},
				},
			},
			want: true,
		},
		{
			filename: "sigma/net_connection_lnx_susp_malware_callback_port.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"Initiated":       "true",
					"DestinationPort": "2222",
					"DestinationIp":   "192.0.2.100",
				},
			},
			want: true,
		},
		{
			filename: "sigma/net_connection_lnx_susp_malware_callback_port.yml",
			entry: &LogEntry{
				Fields: map[string]string{
					"Initiated":       "true",
					"DestinationPort": "2222",
					"DestinationIp":   "127.0.0.1",
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
		got := rule.Detection.Matches(test.entry, test.options)
		if got != test.want {
			t.Errorf("ParseRule(%q).Detection.Matches(%+v, %+v) = %t; want %t",
				test.filename, test.entry, test.options, got, test.want)
		}
	}
}

// MockFieldResolver is a test implementation of FieldResolver
type MockFieldResolver struct {
	// Mappings defines field name patterns to their resolved values
	Mappings map[string][]string
}

func (m *MockFieldResolver) Resolve(fieldName string, entry *LogEntry) []string {
	if values, ok := m.Mappings[fieldName]; ok {
		return values
	}
	return nil
}

func TestFieldResolver(t *testing.T) {
	tests := []struct {
		name     string
		atom     *SearchAtom
		entry    *LogEntry
		resolver *MockFieldResolver
		want     bool
	}{
		{
			name: "resolver returns single matching value",
			atom: &SearchAtom{
				Field:    "custom.field.path",
				Patterns: []string{"expected_value"},
			},
			entry: &LogEntry{
				Fields: map[string]string{
					"other_field": "irrelevant",
				},
			},
			resolver: &MockFieldResolver{
				Mappings: map[string][]string{
					"custom.field.path": {"expected_value"},
				},
			},
			want: true,
		},
		{
			name: "resolver returns multiple values, one matches",
			atom: &SearchAtom{
				Field:    "array.field",
				Patterns: []string{"target_value"},
			},
			entry: &LogEntry{
				Fields: map[string]string{},
			},
			resolver: &MockFieldResolver{
				Mappings: map[string][]string{
					"array.field": {"wrong_value", "target_value", "another_value"},
				},
			},
			want: true,
		},
		{
			name: "resolver returns multiple values, none match",
			atom: &SearchAtom{
				Field:    "array.field",
				Patterns: []string{"target_value"},
			},
			entry: &LogEntry{
				Fields: map[string]string{},
			},
			resolver: &MockFieldResolver{
				Mappings: map[string][]string{
					"array.field": {"wrong_value", "another_wrong_value"},
				},
			},
			want: false,
		},
		{
			name: "resolver returns no values for field",
			atom: &SearchAtom{
				Field:    "missing.field",
				Patterns: []string{"any_value"},
			},
			entry: &LogEntry{
				Fields: map[string]string{},
			},
			resolver: &MockFieldResolver{
				Mappings: map[string][]string{},
			},
			want: false,
		},
		{
			name: "resolver returns empty slice",
			atom: &SearchAtom{
				Field:    "empty.field",
				Patterns: []string{"any_value"},
			},
			entry: &LogEntry{
				Fields: map[string]string{},
			},
			resolver: &MockFieldResolver{
				Mappings: map[string][]string{
					"empty.field": {},
				},
			},
			want: false,
		},
		{
			name: "resolver with wildcard-like pattern",
			atom: &SearchAtom{
				Field:    "field1.*.field2",
				Patterns: []string{"matched_value"},
			},
			entry: &LogEntry{
				Fields: map[string]string{
					"field1.abc.field2": "wrong_value", // This would normally match in basic lookup
				},
			},
			resolver: &MockFieldResolver{
				Mappings: map[string][]string{
					"field1.*.field2": {"matched_value", "other_value"},
				},
			},
			want: true,
		},
		{
			name: "resolver with contains modifier",
			atom: &SearchAtom{
				Field:     "complex.path",
				Modifiers: []string{"contains"},
				Patterns:  []string{"admin"},
			},
			entry: &LogEntry{
				Fields: map[string]string{},
			},
			resolver: &MockFieldResolver{
				Mappings: map[string][]string{
					"complex.path": {"user_administrator", "regular_user"},
				},
			},
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := &MatchOptions{
				FieldResolver: test.resolver,
			}
			got := test.atom.ExprMatches(test.entry, opts)
			if got != test.want {
				t.Errorf("SearchAtom.ExprMatches() with resolver = %t; want %t", got, test.want)
			}
		})
	}
}

func TestFieldResolverBackwardCompatibility(t *testing.T) {
	// Test that when no resolver is provided, it falls back to standard field lookup
	atom := &SearchAtom{
		Field:    "standard.field",
		Patterns: []string{"test_value"},
	}

	entry := &LogEntry{
		Fields: map[string]string{
			"standard.field": "test_value",
			"other.field":    "other_value",
		},
	}

	// Without resolver - should use standard lookup
	opts1 := &MatchOptions{}
	got1 := atom.ExprMatches(entry, opts1)
	if !got1 {
		t.Error("Expected standard field lookup to work when no resolver provided")
	}

	// With nil resolver - should use standard lookup
	opts2 := &MatchOptions{FieldResolver: nil}
	got2 := atom.ExprMatches(entry, opts2)
	if !got2 {
		t.Error("Expected standard field lookup to work when resolver is nil")
	}

	// Verify case-insensitive fallback still works
	atomCaseInsensitive := &SearchAtom{
		Field:    "STANDARD.FIELD",
		Patterns: []string{"test_value"},
	}
	got3 := atomCaseInsensitive.ExprMatches(entry, opts1)
	if !got3 {
		t.Error("Expected case-insensitive lookup to work without resolver")
	}
}

func TestFieldResolverEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		atom     *SearchAtom
		entry    *LogEntry
		resolver *MockFieldResolver
		want     bool
	}{
		{
			name: "resolver returns nil (not empty slice)",
			atom: &SearchAtom{
				Field:    "missing.field",
				Patterns: []string{"any_value"},
			},
			entry: &LogEntry{
				Fields: map[string]string{},
			},
			resolver: &MockFieldResolver{
				Mappings: map[string][]string{}, // Will return nil for missing field
			},
			want: false,
		},
		{
			name: "resolver with complex field path",
			atom: &SearchAtom{
				Field:    "deep.nested.array[*].field",
				Patterns: []string{"target"},
			},
			entry: &LogEntry{
				Fields: map[string]string{
					"irrelevant": "data",
				},
			},
			resolver: &MockFieldResolver{
				Mappings: map[string][]string{
					"deep.nested.array[*].field": {"value1", "target", "value3"},
				},
			},
			want: true,
		},
		{
			name: "resolver with regex modifier",
			atom: &SearchAtom{
				Field:     "pattern.field",
				Modifiers: []string{"re"},
				Patterns:  []string{"^test.*end$"},
			},
			entry: &LogEntry{
				Fields: map[string]string{},
			},
			resolver: &MockFieldResolver{
				Mappings: map[string][]string{
					"pattern.field": {"test_middle_end", "no_match", "another_test_end"},
				},
			},
			want: true,
		},
		{
			name: "resolver with startswith modifier on multiple values",
			atom: &SearchAtom{
				Field:     "prefix.field",
				Modifiers: []string{"startswith"},
				Patterns:  []string{"admin"},
			},
			entry: &LogEntry{
				Fields: map[string]string{},
			},
			resolver: &MockFieldResolver{
				Mappings: map[string][]string{
					"prefix.field": {"user_normal", "administrator", "admin_user"},
				},
			},
			want: true,
		},
		{
			name: "resolver with all+contains modifier requires all patterns to match",
			atom: &SearchAtom{
				Field:     "all.field",
				Modifiers: []string{"all", "contains"},
				Patterns:  []string{"test", "admin"},
			},
			entry: &LogEntry{
				Fields: map[string]string{},
			},
			resolver: &MockFieldResolver{
				Mappings: map[string][]string{
					"all.field": {"test_admin_user"}, // Contains both "test" and "admin"
				},
			},
			want: true,
		},
		{
			name: "resolver with all+contains modifier fails when one pattern missing",
			atom: &SearchAtom{
				Field:     "all.field",
				Modifiers: []string{"all", "contains"},
				Patterns:  []string{"test", "admin"},
			},
			entry: &LogEntry{
				Fields: map[string]string{},
			},
			resolver: &MockFieldResolver{
				Mappings: map[string][]string{
					"all.field": {"test_user"}, // Missing "admin"
				},
			},
			want: false,
		},
		{
			name: "message field should ignore resolver",
			atom: &SearchAtom{
				Field:    "", // Empty field means message
				Patterns: []string{"hello"},
			},
			entry: &LogEntry{
				Message: "hello world",
				Fields:  map[string]string{},
			},
			resolver: &MockFieldResolver{
				Mappings: map[string][]string{
					"": {"should_not_be_called"},
				},
			},
			want: true, // Should match message, not call resolver
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := &MatchOptions{
				FieldResolver: test.resolver,
			}
			got := test.atom.ExprMatches(test.entry, opts)
			if got != test.want {
				t.Errorf("SearchAtom.ExprMatches() = %t; want %t", got, test.want)
			}
		})
	}
}

func TestFieldResolverWithPlaceholders(t *testing.T) {
	// Test that resolvers work correctly with placeholder expansion
	atom := &SearchAtom{
		Field:     "dynamic.field",
		Modifiers: []string{"expand"},
		Patterns:  []string{"%test_placeholder%"},
	}

	entry := &LogEntry{
		Fields: map[string]string{},
	}

	resolver := &MockFieldResolver{
		Mappings: map[string][]string{
			"dynamic.field": {"expanded_value", "other_value"},
		},
	}

	opts := &MatchOptions{
		FieldResolver: resolver,
		Placeholders: map[string][]string{
			"test_placeholder": {"expanded_value"},
		},
	}

	got := atom.ExprMatches(entry, opts)
	if !got {
		t.Error("Expected resolver to work with placeholder expansion")
	}
}
