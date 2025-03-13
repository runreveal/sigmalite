# Sigmalite Risk Score Documentation

## Overview

The Risk Score feature in Sigmalite allows more granular scoring of alerts beyond the standard Sigma rule level categorization (informational, low, medium, high, critical). With risk scoring, you can assign different severity scores to alerts based on specific combinations of detection conditions.

## How Risk Scoring Works

Risk scoring is implemented through the `risk_score` section in a Sigma rule YAML file. This feature allows you to:

1. Define a default base score for the rule
2. Specify different scores based on specific condition expressions
3. Use complex boolean logic with AND, OR, and NOT operators to create precise scoring conditions

## Rule Configuration

To add risk scoring to a Sigma rule, include a `risk_score` section like this:

```yaml
risk_score:
  default: 50               # Base score when no specific condition matches
  scores:
    selection_a: 30                              # Simple selection match
    selection_a AND selection_b: 60              # Both selections match
    selection_a AND NOT selection_b: 70          # One matches, one doesn't
    selection_a OR selection_b: 40               # Either selection matches
    selection_a AND (selection_b OR selection_c): 80  # More complex combinations
```

### Score Meanings

Score values typically follow this scale:

- 0-20: Informational (minimal risk)
- 21-40: Low risk
- 41-60: Medium risk
- 61-80: High risk
- 81-100: Critical risk

The specific meaning of scores may vary based on your organization's security policies and risk assessment.

## Usage Examples

### Basic Example

```yaml
title: Suspicious AWS CloudTrail Activity
detection:
  selection_source:
    eventSource: cloudtrail.amazonaws.com
    eventName:
      - StopLogging
      - UpdateTrail
      - DeleteTrail
  selection_encoded:
    userAgent: '*.amazonaws.com'
  condition: selection_source
  
risk_score:
  default: 50
  scores:
    selection_source AND NOT selection_encoded: 70  # Higher risk if from non-AWS user agent
    selection_source AND selection_encoded: 60      # Slightly lower risk if from AWS user agent
```

In this example:
- Events matching just `selection_source` get the default score of 50
- Events matching `selection_source` but not `selection_encoded` get a higher score of 70
- Events matching both `selection_source` and `selection_encoded` get a score of 60

### Network Example

```yaml
title: Suspicious Outbound Connection
detection:
  selection_destination:
    DestinationIp:
      - '203.0.113.*'
      - '198.51.100.*'
  selection_port:
    DestinationPort:
      - '4444'
      - '8080'
  selection_process:
    ProcessName:
      - 'powershell.exe'
      - 'cmd.exe'
  condition: selection_destination AND (selection_port OR selection_process)

risk_score:
  default: 40
  scores:
    selection_destination AND selection_port AND selection_process: 90
    selection_destination AND selection_port: 70
    selection_destination AND selection_process: 60
```

In this example, the combined presence of suspicious destination, port, and process creates a much higher risk score of 90.

## Programmatic Access

To evaluate risk scores programmatically, use the `EvaluateRiskScore` method on a Rule:

```go
// Evaluate risk score for a log entry
result := rule.EvaluateRiskScore(logEntry, nil)

// Access the results
if result.Matched {
    fmt.Printf("Risk score: %d\n", result.Score)
    fmt.Printf("Matched expression: %s\n", result.Expression)
}
```

The result includes:
- `Score`: The numeric risk score value
- `Matched`: Whether the entry matched any detection conditions
- `Expression`: The specific expression that matched (for debugging or explanation)

## Best Practices

1. **Start with default score**: Always set a sensible default score based on the rule's general criticality
2. **Be specific**: Create scoring expressions for specific condition combinations that merit higher or lower risk scores
3. **Follow a scale**: Be consistent in your scoring scale across rules
4. **Document your thresholds**: Include comments in rules explaining why certain conditions get specific scores
5. **Avoid overlapping conditions**: Be careful with expression ordering to ensure deterministic scoring
6. **Test thoroughly**: Verify that your scoring expressions behave as expected with sample data

## Ordered Expression Evaluation

Starting with version 1.x, Sigmalite evaluates risk scoring expressions in the order they are defined in the YAML file. This provides better control over which score is assigned when multiple expressions could match the same event.

For example:

```yaml
risk_score:
  default: 50
  scores:
    selection_a AND selection_b: 90    # Checked first
    selection_a: 70                    # Checked second
    selection_b: 60                    # Checked third
```

In this example:
- If both `selection_a` AND `selection_b` match, the score will be 90
- If only `selection_a` matches, the score will be 70
- If only `selection_b` matches, the score will be 60
- If none match, the default score of 50 will be used

This ordered evaluation allows you to define more specific conditions first, followed by more general conditions. Previously, multiple matching expressions might have led to unpredictable results.

## Limitations

- Boolean expressions are evaluated left-to-right (no operator precedence)
- Complex nested expressions might require careful formatting and testing
- Performance may be impacted with many complex scoring expressions
- YAML map keys are not guaranteed to preserve order in all parsers, though most modern parsers do maintain insertion order