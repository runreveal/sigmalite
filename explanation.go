// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigmalite

import (
	"fmt"
	"strings"
)

type traceNode struct {
	Type       string
	Name       string
	Matched    bool
	Field      string
	Pattern    []string
	FieldValue string
	Reason     string
	Children   []*traceNode
}

type explanationContext struct {
	root  *traceNode
	stack []*traceNode
}

func newExplanationContext() *explanationContext {
	return &explanationContext{
		stack: make([]*traceNode, 0, 16),
	}
}

func (ctx *explanationContext) push(node *traceNode) {
	if len(ctx.stack) > 0 {
		parent := ctx.stack[len(ctx.stack)-1]
		parent.Children = append(parent.Children, node)
	} else {
		ctx.root = node
	}
	ctx.stack = append(ctx.stack, node)
}

func (ctx *explanationContext) pop() {
	if len(ctx.stack) > 0 {
		ctx.stack = ctx.stack[:len(ctx.stack)-1]
	}
}

func (ctx *explanationContext) Format() string {
	if ctx.root == nil {
		return ""
	}
	var sb strings.Builder
	ctx.root.format(&sb, 0)
	return sb.String()
}

func (node *traceNode) format(sb *strings.Builder, indent int) {
	prefix := strings.Repeat("  ", indent)
	symbol := "✓"
	if !node.Matched {
		symbol = "✗"
	}

	switch node.Type {
	case "and":
		sb.WriteString(fmt.Sprintf("%s[AND] %s", prefix, symbol))
		if node.Reason != "" {
			sb.WriteString(fmt.Sprintf(" - %s", node.Reason))
		}
		sb.WriteString("\n")
	case "or":
		sb.WriteString(fmt.Sprintf("%s[OR] %s", prefix, symbol))
		if node.Reason != "" {
			sb.WriteString(fmt.Sprintf(" - %s", node.Reason))
		}
		sb.WriteString("\n")
	case "not":
		sb.WriteString(fmt.Sprintf("%s[NOT] %s", prefix, symbol))
		if node.Reason != "" {
			sb.WriteString(fmt.Sprintf(" - %s", node.Reason))
		}
		sb.WriteString("\n")
	case "named":
		sb.WriteString(fmt.Sprintf("%s[%s] %s\n", prefix, node.Name, symbol))
	case "atom":
		fieldName := node.Field
		if fieldName == "" {
			fieldName = "<message>"
		}
		sb.WriteString(fmt.Sprintf("%s[%s] %s\n", prefix, fieldName, symbol))
		if node.FieldValue != "" {
			sb.WriteString(fmt.Sprintf("%s  Value: %q\n", prefix, node.FieldValue))
		} else {
			sb.WriteString(fmt.Sprintf("%s  Value: <not found>\n", prefix))
		}
		if len(node.Pattern) > 0 {
			sb.WriteString(fmt.Sprintf("%s  Pattern: %v\n", prefix, node.Pattern))
		}
		if node.Reason != "" {
			sb.WriteString(fmt.Sprintf("%s  Reason: %s\n", prefix, node.Reason))
		}
	}

	for _, child := range node.Children {
		child.format(sb, indent+1)
	}
}
