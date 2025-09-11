# `github.com/runreveal/sigmalite`

Package `sigmalite` provides a parser and an execution engine
for the [Sigma detection format][].

```go
rule, err := sigmalite.ParseRule([]byte(`
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
  return err
}
entry := &sigmalite.LogEntry{
  Message: "Hello foo",
  Fields: map[string]string{
    "EventId": "1234",
  },
}
isMatch := rule.Detection.Matches(entry, nil)
```

[Sigma detection format]: https://sigmahq.io/

## Install

```shell
go get github.com/runreveal/sigmalite
```

## Rules

Rules are written in [YAML][] format
and, at a minimum, must include a `title` and a `detection`:

```yaml
title: My example rule
detection:
  keywords:
    - foo
    - bar
  selection:
    EventId: 1234
  condition: keywords and selection
```

The `condition` field in the `detection` block is a logical expression
that joins other field selectors in the `detection` block.
In this example, this rule will match any log entry
that has an `EventId` field that is exactly `1234`
_and_ has "foo" _or_ "bar" in its message.

Fields can also be matched using [regular expressions][]:

```yaml
title: My example rule with a timestamp
detection:
  selection:
    Timestamp|re: ^2024-06-01T(01|02|03):[0-5][0-9]:[0-5][0-9]$
  condition: selection
```

As well as [CIDRs][CIDR]:

```yaml
title: My example rule with IP addresses
detection:
  local:
    DestinationIp|cidr:
      - "127.0.0.0/8"
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
      - "169.254.0.0/16"
      - "::1/128" # IPv6 loopback
      - "fe80::/10" # IPv6 link-local addresses
      - "fc00::/7" # IPv6 private addresses
  condition: not local
```

More information can be found in the [official Sigma rules documentation][].

[CIDR]: https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing
[official Sigma rules documentation]: https://sigmahq.io/docs/basics/rules.html
[regular expressions]: https://go.dev/s/re2syntax
[YAML]: https://yaml.org/

### Field Modifiers

This library supports the following [field modifiers][]:

- [`all`](https://sigmahq.io/docs/basics/modifiers.html#all)
- [`cidr`](https://sigmahq.io/docs/basics/modifiers.html#cidr)
- [`contains`](https://sigmahq.io/docs/basics/modifiers.html#contains)
- [`endswith`](https://sigmahq.io/docs/basics/modifiers.html#endswith)
- [`expand`](https://sigmahq.io/docs/basics/modifiers.html#expand)
- [`re`](https://sigmahq.io/docs/basics/modifiers.html#re)
- [`startswith`](https://sigmahq.io/docs/basics/modifiers.html#startswith)
- [`windash`](https://sigmahq.io/docs/basics/modifiers.html#windash)
- [`base64/base64offset`](https://sigmahq.io/docs/basics/modifiers.html#base64-base64offset)

[field modifiers]: https://sigmahq.io/docs/basics/modifiers.html

### Field Resolver

The `FieldResolver` interface extends the standard Sigma specification to support complex field lookup scenarios that go beyond simple key/value pairs. This allows you to implement custom field resolution logic for:

- **Nested JSON structures**: Access deeply nested fields using dot notation (e.g., `event.process.user`)
- **Array handling**: Extract values from arrays or lists within log entries
- **Wildcard matching**: Support field patterns like `process.*.user` or `network[*].ip`
- **Multiple field aggregation**: Combine values from multiple related fields
- **Case normalization**: Handle field name variations and case sensitivity
- **Complex data transformations**: Apply custom logic before field matching
- **External datasource lookups**: Lookup field values from an external datasource.

#### Interface Definition

```go
type FieldResolver interface {
    Resolve(fieldName string, entry *LogEntry) []string
}
```

The `Resolve` method takes a field name from your Sigma rule and returns all matching values as a string slice. If no matches are found, return `nil` or an empty slice.

#### Basic Usage Example

```go
// CustomResolver demonstrates field resolution for structured logs
type CustomResolver struct{}

func (r *CustomResolver) Resolve(fieldName string, entry *sigma.LogEntry) []string {
    switch fieldName {
    case "process.users":
        // Aggregate user fields from multiple sources
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

    case "network.internal_ips":
        // Extract all IP addresses from network-related fields
        var ips []string
        for fieldName, value := range entry.Fields {
            if strings.Contains(strings.ToLower(fieldName), "ip") {
                // Simple IP validation (in real usage, use proper validation)
                if strings.Contains(value, ".") {
                    ips = append(ips, value)
                }
            }
        }
        return ips

    default:
        return nil
    }
}

func matches(detection *sigmalite.Detection) bool {
  opts := &sigmalite.MatchOptions{
		FieldResolver: CustomResolver{},
  },

  entry := &sigmalite.LogEntry{
		Message: string("Message Text"),
		Fields:  nil, // Using resolver so this can be empty
	}

	return detection.Matches(entry, opts)
}

```

Field Resolvers work seamlessly with all [field modifiers](#field-modifiers), allowing you to apply regex patterns, case-insensitive matching, and other transformations to the resolved values.

## License

[Apache 2.0](LICENSE)
