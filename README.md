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
      - '127.0.0.0/8'
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
      - '169.254.0.0/16'
      - '::1/128'         # IPv6 loopback
      - 'fe80::/10'       # IPv6 link-local addresses
      - 'fc00::/7'        # IPv6 private addresses
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

[field modifiers]: https://sigmahq.io/docs/basics/modifiers.html

## License

[Apache 2.0](LICENSE)
