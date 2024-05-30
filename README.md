# `github.com/runreveal/sigma`

Package `sigma` provides a parser and an execution engine
for the [Sigma detection format][].

```go
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
  return err
}
entry := &sigma.LogEntry{
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
go get github.com/runreveal/sigma
```

## License

[Apache 2.0](LICENSE)
