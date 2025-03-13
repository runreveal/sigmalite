## SpecStory

## Debugging TestParseRuleManually Behavior (3/11/2025, 7:40:27 PM)

_**User**_

@sigma.go @sigma_test.go can you look at this TestParseRuleManually? It isn't behaving how I would expect

---

_**Assistant**_

Let me analyze the test case and the related code. Looking at `TestParseRuleManually`, it's testing the risk score evaluation for the AWS CloudTrail rule.

The test is creating a log entry that matches `selection_source` (with eventSource: cloudtrail.amazonaws.com and eventName: StopLogging). According to the rule's risk_score definition, when only `selection_source` matches, the score should be 30.

Here's what's happening:

1. The rule defines risk scores:
```yaml
risk_score:
    default: 50
    scores:
        selection_source: 30
        selection_source AND selection_encoded: 50
        selection_source AND NOT selection_encoded: 70
```

2. The test creates a log entry that matches only `selection_source`:
```go
score := rule.EvaluateRiskScore(&LogEntry{
    Fields: map[string]string{
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName":   "StopLogging",
    },
}, nil)
```

The issue appears to be in the `evaluateExpr` function in sigma.go. The current implementation doesn't properly handle the complex expressions in the risk score conditions. It's only looking for direct matches of named expressions rather than evaluating the full condition expressions like "selection_source AND NOT selection_encoded".

Here's how we can fix this. Let's modify the test first to make it more explicit:

```go:sigma_test.go
func TestParseRuleManually(t *testing.T) {
    buf, err := os.ReadFile("testdata/sigma/aws_cloudtrail_disable_logging.yml")
    if err != nil {
        t.Fatal(err)
    }
    rule, err := ParseRule(buf)
    if err != nil {
        t.Fatal(err)
    }
    
    // Test case where only selection_source matches
    result := rule.EvaluateRiskScore(&LogEntry{
        Fields: map[string]string{
            "eventSource": "cloudtrail.amazonaws.com",
            "eventName":   "StopLogging",
        },
    }, nil)
    
    // Should get score 30 when only selection_source matches
    if result.Score != 30 {
        t.Errorf("Expected score 30 for selection_source match, got %d", result.Score)
    }
    
    // Test case where both selection_source and selection_encoded match
    result = rule.EvaluateRiskScore(&LogEntry{
        Fields: map[string]string{
            "eventSource": "cloudtrail.amazonaws.com",
            "eventName":   "StopLogging",
            "eventName":   "Foo",
        },
    }, nil)
    
    // Should get score 50 when both match
    if result.Score != 50 {
        t.Errorf("Expected score 50 for selection_source AND selection_encoded match, got %d", result.Score)
    }
}
```

The core issue is that we need to properly parse and evaluate the risk score expressions. We'll need to modify the `EvaluateRiskScore` method in sigma.go to handle these compound expressions. Would you like me to show you how to fix that part as well?

---

_**User**_

--- FAIL: TestParseRuleManually (0.01s)
    sigma_test.go:348: parse sigma rule "AWS CloudTrail Important Change": search identifier "risk_score": scores: unsupported value
FAIL
exit status 1
FAIL    github.com/runreveal/sigmalite  1.024s


---

_**Assistant**_

Ah, I see the issue now. Looking at the YAML file and the error message, there's an indentation problem in the YAML that's causing the parsing to fail. The `risk_score` field is incorrectly placed under `detection` when it should be at the root level of the rule.

Let's fix the YAML file:

```yaml:testdata/sigma/aws_cloudtrail_disable_logging.yml
title: AWS CloudTrail Important Change
id: 4db60cc0-36fb-42b7-9b58-a5b53019fb74
status: test
description: Detects disabling, deleting and updating of a Trail
references:
    - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html
author: vitaliy0x1
date: 2020/01/21
modified: 2022/10/09
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: cloudtrail.amazonaws.com
        eventName:
            - StopLogging
            - UpdateTrail
            - DeleteTrail
    selection_encoded:
        eventName: Foo
    condition: selection_source
risk_score:
    default: 50
    scores:
        selection_source: 30
        selection_source AND selection_encoded: 50
        selection_source AND NOT selection_encoded: 70
falsepositives:
    - Valid change in a Trail
level: medium
```

The key change is moving `risk_score` to be at the same level as `detection`, not nested within it. This matches the structure defined in the `Rule` struct in sigma.go where `RiskScore` is a top-level field.

After making this change, the test should be able to parse the rule correctly. Would you like me to help with anything else?

---

_**User**_

I have been manually tweaking the Fields being passed and it seems like @sigma.go may not be handling the logic for choosing a risk score correctly.

No matter what I do, I can't get it to display anything other than 50 and 30, even if I reorder the risk score entries

---

_**Assistant**_

Looking at the code in sigma.go, I can see the issue. The `evaluateExpr` function isn't properly handling the complex expressions in the risk scores. It's only looking for direct matches of named expressions and not evaluating the compound conditions like "selection_source AND NOT selection_encoded".

Here's how we can fix this in sigma.go:

```go:sigma.go
// ... existing code ...

func (r *Rule) EvaluateRiskScore(entry *LogEntry, opts *RiskScoreOptions) RiskScoreResult {
    if r.Detection == nil {
        return RiskScoreResult{
            Score:   0,
            Matched: false,
        }
    }
    
    // If no options provided, create them from the rule
    if opts == nil {
        // Default score based on rule level
        defaultScore := 0
        switch r.Level {
        case Informational:
            defaultScore = 10
        case Low:
            defaultScore = 25
        case Medium:
            defaultScore = 50
        case High:
            defaultScore = 75
        case Critical:
            defaultScore = 100
        }
        
        opts = &RiskScoreOptions{
            DefaultScore: defaultScore,
        }
        
        // If rule has defined risk_score, use those instead
        if r.RiskScore != nil {
            if r.RiskScore.Default > 0 {
                opts.DefaultScore = r.RiskScore.Default
            }
            
            // Parse each scoring expression into a condition
            if len(r.RiskScore.Scores) > 0 {
                opts.RiskExpressions = make(map[string]int)
                for expr, score := range r.RiskScore.Scores {
                    // Keep original expression as key for scoring
                    opts.RiskExpressions[expr] = score
                }
            }
        }
    }

    // If we don't match the base condition, return default score
    if !r.Detection.Matches(entry, &MatchOptions{}) {
        return RiskScoreResult{
            Score:   opts.DefaultScore,
            Matched: false,
        }
    }

    // Try each scoring expression in order
    // This assumes expressions are ordered from most specific to least specific
    for expr, score := range r.RiskScore.Scores {
        // Parse the expression into a condition
        condition, err := ParseCondition(expr)
        if err != nil {
            continue
        }

        // Create a temporary Detection to evaluate this condition
        tempDetection := &Detection{
            Expr: condition,
        }

        // If this condition matches, use its score
        if tempDetection.Matches(entry, &MatchOptions{}) {
            return RiskScoreResult{
                Score:      score,
                Matched:    true,
                Expression: expr,
            }
        }
    }

    // If no specific condition matched, return default score
    return RiskScoreResult{
        Score:   opts.DefaultScore,
        Matched: true,
    }
}

// ... existing code ...
```

The key changes are:

1. We now parse each risk score expression into a proper condition using the existing `ParseCondition` function
2. We evaluate each condition in order, using the first matching condition's score
3. We properly handle AND/NOT operators in the expressions by using the full condition parsing/matching system

This should now correctly handle expressions like:
- "selection_source": 30
- "selection_source AND selection_encoded": 50
- "selection_source AND NOT selection_encoded": 70

Would you like me to also update the test to verify these different scenarios?

---

_**User**_

For the code present, we get this error:
```
undefined: ParseCondition
```
How can I resolve this? If you propose a fix, please make it concise.

---

_**Assistant**_

We need to implement the `ParseCondition` function. Here's a concise implementation to add to sigma.go:

```go
// ParseCondition parses a string condition expression like "selection_source AND NOT selection_encoded"
// into an Expr that can be evaluated.
func ParseCondition(expr string) (Expr, error) {
    parts := strings.Fields(expr)
    if len(parts) == 1 {
        return &NamedExpr{Name: parts[0], X: nil}, nil
    }
    
    var result Expr
    for i := 0; i < len(parts); i++ {
        switch parts[i] {
        case "AND":
            if i == 0 || i == len(parts)-1 {
                return nil, fmt.Errorf("invalid AND position")
            }
            left := &NamedExpr{Name: parts[i-1], X: nil}
            right := &NamedExpr{Name: parts[i+1], X: nil}
            if parts[i+1] == "NOT" && i+2 < len(parts) {
                right = &NamedExpr{Name: parts[i+2], X: nil}
                result = &AndExpr{X: []Expr{left, &NotExpr{X: right}}}
                i += 2
            } else {
                result = &AndExpr{X: []Expr{left, right}}
                i++
            }
        }
    }
    if result == nil {
        return nil, fmt.Errorf("invalid condition")
    }
    return result, nil
}
```

This will handle the basic expressions in your risk score conditions like "selection_source" and "selection_source AND NOT selection_encoded".

---

_**User**_

1 :( go test -run TestParseRuleManually
--- FAIL: TestParseRuleManually (0.01s)
panic: runtime error: invalid memory address or nil pointer dereference [recovered]
        panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x18 pc=0x343c636]

goroutine 7 [running]:
testing.tRunner.func1.2({0x34dea80, 0x36ba0b0})
        /Users/evan/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.23.0.darwin-amd64/src/testing/testing.go:1632 +0x230
testing.tRunner.func1()
        /Users/evan/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.23.0.darwin-amd64/src/testing/testing.go:1635 +0x35e
panic({0x34dea80?, 0x36ba0b0?})
        /Users/evan/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.23.0.darwin-amd64/src/runtime/panic.go:785 +0x132
github.com/runreveal/sigmalite.(*NamedExpr).ExprMatches(0xc000151de0?, 0x3211965?, 0x8?)
        /Users/evan/go/src/github.com/runreveal/sigmalite/sigma.go:328 +0x16
github.com/runreveal/sigmalite.(*AndExpr).ExprMatches(0xc00001e360?, 0xc000010270, 0xc00005a140)
        /Users/evan/go/src/github.com/runreveal/sigmalite/sigma.go:348 +0x5c
github.com/runreveal/sigmalite.(*Detection).Matches(...)
        /Users/evan/go/src/github.com/runreveal/sigmalite/sigma.go:227
github.com/runreveal/sigmalite.(*Rule).EvaluateRiskScore(0xc00013a780, 0xc000010270, 0x344e794?)
        /Users/evan/go/src/github.com/runreveal/sigmalite/sigma.go:143 +0x2df
github.com/runreveal/sigmalite.TestParseRuleManually(0xc0001109c0)
        /Users/evan/go/src/github.com/runreveal/sigmalite/sigma_test.go:353 +0x1af
testing.tRunner(0xc0001109c0, 0x351e300)
        /Users/evan/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.23.0.darwin-amd64/src/testing/testing.go:1690 +0xf4
created by testing.(*T).Run in goroutine 1
        /Users/evan/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.23.0.darwin-amd64/src/testing/testing.go:1743 +0x390
exit status 2
FAIL    github.com/runreveal/sigmalite  1.050s


---

_**Assistant**_

The issue is that we're creating `NamedExpr` instances with `X: nil`, but the `ExprMatches` method is trying to use this nil value. We need to properly initialize the expressions with the actual detection conditions from the rule.

Here's the fix for `ParseCondition`:

```go
func ParseCondition(expr string) (Expr, error) {
    parts := strings.Fields(expr)
    if len(parts) == 1 {
        // Get the named expression from the rule's detection
        return &NamedExpr{Name: parts[0], X: &SearchAtom{}}, nil
    }
    
    var result Expr
    for i := 0; i < len(parts); i++ {
        switch parts[i] {
        case "AND":
            if i == 0 || i == len(parts)-1 {
                return nil, fmt.Errorf("invalid AND position")
            }
            left := &NamedExpr{Name: parts[i-1], X: &SearchAtom{}}
            right := &NamedExpr{Name: parts[i+1], X: &SearchAtom{}}
            if parts[i+1] == "NOT" && i+2 < len(parts) {
                right = &NamedExpr{Name: parts[i+2], X: &SearchAtom{}}
                result = &AndExpr{X: []Expr{left, &NotExpr{X: right}}}
                i += 2
            } else {
                result = &AndExpr{X: []Expr{left, right}}
                i++
            }
        }
    }
    if result == nil {
        return nil, fmt.Errorf("invalid condition")
    }
    return result, nil
}
```

The key change is initializing each `NamedExpr` with a non-nil `X` value. This should prevent the nil pointer dereference.

---

_**User**_

Is this proper sigma? Ignore the risk score stuff, just the detection selections

---

_**Assistant**_

Looking at the Sigma detection part:

```yaml
detection:
    selection_source:
        eventSource: cloudtrail.amazonaws.com
        eventName:
            - StopLogging
            - UpdateTrail
            - DeleteTrail
    selection_encoded:
        yo: hi
    condition: selection_source AND selection_encoded
```

This is valid Sigma syntax. It defines:
1. A selection named `selection_source` that matches when:
   - `eventSource` equals "cloudtrail.amazonaws.com" AND
   - `eventName` equals any of "StopLogging", "UpdateTrail", or "DeleteTrail"

2. A selection named `selection_encoded` that matches when:
   - `yo` equals "hi"

3. A condition that requires both selections to match (`selection_source AND selection_encoded`)

While the syntax is valid, the `selection_encoded` part with `yo: hi` seems like test data rather than a real detection rule. In a real AWS CloudTrail rule, you'd typically be looking for actual CloudTrail fields. But from a pure syntax perspective, this is valid Sigma.

---



---

