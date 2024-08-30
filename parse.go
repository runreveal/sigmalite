// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigma

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

var WinDashMatcher = regexp.MustCompile(`\B[-/]\b`)

const EnDash = "–"
const EmDash = "—"
const HorizontalBar = "―"

type yamlRule struct {
	Title          string               `yaml:"title"`
	ID             string               `yaml:"id,omitempty"`
	Related        []yamlRelation       `yaml:"related,omitempty"`
	Status         Status               `yaml:"status,omitempty"`
	Description    string               `yaml:"description,omitempty"`
	References     []string             `yaml:"references,omitempty"`
	Author         string               `yaml:"author,omitempty"`
	Date           Date                 `yaml:"date,omitempty"`
	Modified       Date                 `yaml:"modified,omitempty"`
	Tags           []string             `yaml:"tags,omitempty"`
	Level          Level                `yaml:"level,omitempty"`
	LogSource      *LogSource           `yaml:"logsource"`
	Detection      map[string]yaml.Node `yaml:"detection"`
	Fields         []string             `yaml:"fields,omitempty"`
	FalsePositives yaml.Node            `yaml:"falsepositives,omitempty"`
}

type yamlRelation struct {
	ID   string       `yaml:"id"`
	Type RelationType `yaml:"type"`
}

type yamlLogSource struct {
	Category   string `yaml:"category,omitempty"`
	Product    string `yaml:"product,omitempty"`
	Service    string `yaml:"service,omitempty"`
	Definition string `yaml:"definition,omitempty"`
}

// ParseRule parses a single Sigma YAML document.
func ParseRule(data []byte) (*Rule, error) {
	docNode := new(yaml.Node)
	if err := yaml.Unmarshal(data, docNode); err != nil {
		return nil, fmt.Errorf("parse sigma rule: %v", err)
	}
	doc := new(yamlRule)
	if err := docNode.Decode(doc); err != nil {
		return nil, fmt.Errorf("parse sigma rule: %v", err)
	}
	if doc.Title == "" {
		return nil, fmt.Errorf("parse sigma rule: missing title")
	}
	r := &Rule{
		Title:       doc.Title,
		ID:          doc.ID,
		Status:      doc.Status,
		Description: doc.Description,
		References:  doc.References,
		Author:      doc.Author,
		Date:        doc.Date,
		Modified:    doc.Modified,
		Tags:        doc.Tags,
		Level:       doc.Level,

		LogSource: new(LogSource),
		Detection: new(Detection),

		Fields: doc.Fields,

		Extra: extractExtraFields(docNode),
	}

	// Technically the Sigma specification makes this required,
	// but leaves all the fields optional.
	// I'd rather treat an empty map the same as a missing one.
	if doc.LogSource != nil {
		r.LogSource.Category = doc.LogSource.Category
		r.LogSource.Product = doc.LogSource.Product
		r.LogSource.Service = doc.LogSource.Service
		r.LogSource.Definition = doc.LogSource.Definition
	}

	if doc.Detection == nil {
		return nil, fmt.Errorf("parse sigma rule %q: missing detection", r.Title)
	}
	var err error
	r.Detection, err = parseDetection(doc.Detection)
	if err != nil {
		return nil, fmt.Errorf("parse sigma rule %q: %v", r.Title, err)
	}

	if len(doc.Related) > 0 {
		r.Related = make([]Relation, 0, len(doc.Related))
		for i, rel := range doc.Related {
			if rel.ID == "" {
				return nil, fmt.Errorf("parse sigma rule %q: related[%d]: missing id", r.Title, i)
			}
			if rel.Type == "" {
				return nil, fmt.Errorf("parse sigma rule %q: related[%d]: missing type", r.Title, i)
			}
			r.Related = append(r.Related, Relation(rel))
		}
	}

	r.FalsePositives, err = listOfStrings(&doc.FalsePositives)
	if err != nil {
		return nil, fmt.Errorf("parse sigma rule %q: false positives: %v", r.Title, err)
	}

	return r, nil
}

func extractExtraFields(docNode *yaml.Node) map[string]Decoder {
	if docNode.Kind != yaml.DocumentNode || len(docNode.Content) != 1 {
		return nil
	}
	topNode := docNode.Content[0]
	if topNode.Kind != yaml.MappingNode {
		return nil
	}

	m := make(map[string]Decoder)
	for i := 0; i < len(topNode.Content); i += 2 {
		var k string
		if err := topNode.Content[i].Decode(&k); err != nil {
			// Shouldn't occur in practice, but we don't really care about this error.
			continue
		}
		if _, known := knownTopLevelKeys[k]; !known {
			m[k] = topNode.Content[i+1]
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// knownTopLevelKeys is the set of top-level keys that are not considered "extra".
// Adding to this set is technically a breaking change,
// since applications that aren't aware of the new [Rule] field
// will no longer receive the key.
var knownTopLevelKeys = map[string]struct{}{
	"title":          {},
	"id":             {},
	"related":        {},
	"status":         {},
	"description":    {},
	"references":     {},
	"author":         {},
	"date":           {},
	"modified":       {},
	"tags":           {},
	"level":          {},
	"logsource":      {},
	"detection":      {},
	"fields":         {},
	"falsepositives": {},
}

func parseDetection(block map[string]yaml.Node) (*Detection, error) {
	// Check some basics first before we drill into search identifiers.
	docCondition := block["condition"]
	conditions, err := listOfStrings(&docCondition)
	if err != nil {
		return nil, fmt.Errorf("condition: %v", err)
	}
	if len(conditions) == 0 {
		return nil, fmt.Errorf("missing detection condition")
	}
	if _, hasTimeframe := block["timeframe"]; hasTimeframe {
		return nil, fmt.Errorf("timeframe: %v", errAggregate)
	}

	var idents sortedSearchIdentifiers
	for id, x := range block {
		if id == "condition" {
			continue
		}

		var result Expr
		switch x.Kind {
		case yaml.SequenceNode:
			container := new(OrExpr)
			allScalars := true
			for _, elem := range x.Content {
				switch elem.Kind {
				case yaml.ScalarNode:
					var s string
					if err := elem.Decode(&s); err != nil {
						return nil, fmt.Errorf("search identifier %q: %v", id, err)
					}
					container.X = append(container.X, &SearchAtom{
						Patterns: []string{s},
					})
				case yaml.MappingNode:
					allScalars = false
					y, err := parseSearchMap(elem)
					if err != nil {
						return nil, fmt.Errorf("search identifier %q: %v", id, err)
					}
					container.X = append(container.X, y)
				default:
					return nil, fmt.Errorf("search identifier %q: unsupported list value", id)
				}
			}
			switch len(container.X) {
			case 0:
				return nil, fmt.Errorf("search identifier %q: empty list", id)
			case 1:
				result = container.X[0]
			default:
				if allScalars {
					// Optimization: Given a list of strings, turn into a single atom.
					patterns := make([]string, 0, len(container.X))
					for _, elem := range container.X {
						patterns = append(patterns, elem.(*SearchAtom).Patterns...)
					}
					result = &SearchAtom{Patterns: patterns}
				} else {
					result = container
				}
			}
		case yaml.MappingNode:
			y, err := parseSearchMap(&x)
			if err != nil {
				return nil, fmt.Errorf("search identifier %q: %v", id, err)
			}
			result = y
		default:
			return nil, fmt.Errorf("search identifier %q: unsupported value", id)
		}

		idents.insert(&NamedExpr{
			Name: id,
			X:    result,
		})
	}

	container := new(OrExpr)
	for _, cond := range conditions {
		x, err := parseCondition(cond, idents)
		if err != nil {
			return nil, err
		}
		container.X = append(container.X, x)
	}
	d := new(Detection)
	if len(container.X) == 1 {
		d.Expr = container.X[0]
	} else {
		d.Expr = container
	}
	return d, nil
}

type conditionParser struct {
	s           string
	identifiers sortedSearchIdentifiers
}

func parseCondition(condition string, identifiers sortedSearchIdentifiers) (Expr, error) {
	p := conditionParser{
		s:           condition,
		identifiers: identifiers,
	}
	x, err := p.expr()
	if errors.Is(err, errEOF) {
		return nil, fmt.Errorf("condition: empty")
	}
	if err != nil {
		return nil, fmt.Errorf("condition: %v", err)
	}
	if tok := p.lex(); tok != "" {
		return nil, fmt.Errorf("condition: unexpected %q", tok)
	}
	return x, nil
}

func (p *conditionParser) expr() (Expr, error) {
	x, err := p.unary()
	if err != nil {
		return nil, err
	}
	return p.binaryTrail(x, 0)
}

func (p *conditionParser) unary() (Expr, error) {
	tok := p.lex()
	if tok == "" {
		return nil, errEOF
	}
	switch tok {
	case "(":
		x, err := p.expr()
		if errors.Is(err, errEOF) {
			return nil, errors.New("unexpected end of condition after '('")
		}
		if err != nil {
			return nil, err
		}
		tok = p.lex()
		if tok == "" {
			return nil, errors.New("missing ')'")
		}
		return x, nil
	case "not":
		x, err := p.unary()
		if errors.Is(err, errEOF) {
			return nil, errors.New("unexpected end of condition after 'not'")
		}
		if err != nil {
			return nil, err
		}
		return &NotExpr{X: x}, nil
	case "1", "all":
		next := p.lex()
		if next == "" {
			return nil, fmt.Errorf("expected \"of\" after %q (condition ended)", tok)
		}
		if next != "of" {
			return nil, fmt.Errorf("expected \"of\" after %q (found %q)", tok, next)
		}
		next = p.lex()
		if next == "" {
			return nil, fmt.Errorf("expected word after %q (condition ended)", tok+" of")
		}
		identifiers := p.identifiers
		if next != "them" {
			identifiers = identifiers.filter(next)
		}
		switch len(identifiers) {
		case 0:
			return nil, fmt.Errorf("%s of %s did not match any identifiers", tok, next)
		case 1:
			return identifiers[0], nil
		default:
			exprs := make([]Expr, len(identifiers))
			for i, x := range identifiers {
				exprs[i] = x
			}

			switch tok {
			case "1":
				return &OrExpr{X: exprs}, nil
			case "all":
				return &AndExpr{X: exprs}, nil
			default:
				panic("unreachable")
			}
		}
	default:
		x := p.identifiers.find(tok)
		if x == nil {
			return nil, fmt.Errorf("unknown search identifier %s", tok)
		}
		return x, nil
	}
}

// binaryTrail parses zero or more (binaryOp, unaryExpr) sequences.
func (p *conditionParser) binaryTrail(x Expr, minPrecedence int) (Expr, error) {
	for {
		start := p.s
		op := p.lex()
		if op == "" {
			return x, nil
		}
		if op == "|" {
			return nil, errAggregate
		}
		precedence1 := operatorPrecedence(op)
		if precedence1 < 0 || precedence1 < minPrecedence {
			// Not a binary operator or below precedence threshold.
			p.s = start
			return x, nil
		}

		y, err := p.unary()
		if errors.Is(err, errEOF) {
			return nil, fmt.Errorf("unexpected end of condition after %q", op)
		}
		if err != nil {
			return nil, err
		}

		// Resolve any higher precedence operators first.
		for {
			start := p.s
			op2 := p.lex()
			if op2 == "" {
				break
			}
			p.s = start

			precedence2 := operatorPrecedence(op2)
			if precedence2 < 0 || precedence2 <= precedence1 {
				// Not a binary operator or below the precedence of the original operator.
				break
			}
			y, err = p.binaryTrail(y, precedence1+1)
			if err != nil {
				return nil, err
			}
		}

		switch op {
		case "and":
			if ax, ok := x.(*AndExpr); ok {
				ax.X = append(ax.X, y)
			} else {
				x = &AndExpr{
					X: []Expr{x, y},
				}
			}
		case "or":
			if ox, ok := x.(*OrExpr); ok {
				ox.X = append(ox.X, y)
			} else {
				x = &OrExpr{
					X: []Expr{x, y},
				}
			}
		default:
			panic("unreachable")
		}
	}
}

func operatorPrecedence(tok string) int {
	switch tok {
	case "and":
		return 1
	case "or":
		return 0
	default:
		return -1
	}
}

var (
	errEOF       = errors.New("end of condition")
	errAggregate = errors.New("aggregation expressions not supported")
)

// lex returns the next token in the condition
// or the empty string on EOF.
func (p *conditionParser) lex() string {
	p.s = strings.TrimLeftFunc(p.s, unicode.IsSpace)
	var end int
	const delims = "()|"
	switch {
	case p.s == "":
		return ""
	case strings.IndexByte("()|", p.s[0]) != -1:
		end = 1
	default:
		end = strings.IndexFunc(p.s, func(c rune) bool {
			return strings.ContainsRune(delims, c) || unicode.IsSpace(c)
		})
		if end == -1 {
			end = len(p.s)
		}
	}
	tok := p.s[:end]
	p.s = p.s[end:]
	return tok
}

func parseSearchMap(node *yaml.Node) (Expr, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("not a map")
	}
	container := new(AndExpr)
	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]

		var k string
		if err := keyNode.Decode(&k); err != nil {
			return nil, err
		}
		atom := new(SearchAtom)
		var modifiers string
		var ok bool
		atom.Field, modifiers, ok = strings.Cut(k, "|")
		if ok {
			if modifiers == "" {
				return nil, fmt.Errorf("%s: empty modifiers", k)
			}
			atom.Modifiers = strings.Split(modifiers, "|")
		}

		// TODO(maybe): Handle integers differently?
		switch valueNode.Kind {
		case yaml.ScalarNode:
			var v string
			if err := valueNode.Decode(&v); err != nil {
				return nil, fmt.Errorf("%s: %v", k, err)
			}
			atom.Patterns = []string{v}
		case yaml.SequenceNode:
			if err := valueNode.Decode(&atom.Patterns); err != nil {
				return nil, fmt.Errorf("%s: %v", k, err)
			}
		default:
			return nil, fmt.Errorf("%s: unsupported value", k)
		}

		if err := atom.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %v", k, err)
		}
		container.X = append(container.X, atom)
	}

	switch len(container.X) {
	case 0:
		return nil, fmt.Errorf("empty map")
	case 1:
		return container.X[0], nil
	default:
		return container, nil
	}
}

func listOfStrings(node *yaml.Node) ([]string, error) {
	switch node.Kind {
	case 0:
		// Treat missing identically to an empty list.
		return nil, nil
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return nil, err
		}
		return []string{s}, nil
	case yaml.SequenceNode:
		var list []string
		if err := node.Decode(&list); err != nil {
			return nil, err
		}
		return list, nil
	default:
		return nil, errors.New("expected scalar or list of scalars")
	}
}

// sortedSearchIdentifiers is a sorted slice of named expressions.
type sortedSearchIdentifiers []*NamedExpr

func (ssi sortedSearchIdentifiers) find(name string) *NamedExpr {
	i, ok := slices.BinarySearchFunc(ssi, name, compareNamedExpr)
	if !ok {
		return nil
	}
	return ssi[i]
}

func (ssi *sortedSearchIdentifiers) insert(x *NamedExpr) {
	i, ok := slices.BinarySearchFunc(*ssi, x.Name, compareNamedExpr)
	if ok {
		panic(x.Name + " already present")
	}
	*ssi = slices.Insert(*ssi, i, x)
}

// filter returns a new slice that contains only the expressions
// whose name matches the given pattern.
// The pattern may contain asterisk characters ('*')
// to indicate matches of zero or more characters.
func (ssi sortedSearchIdentifiers) filter(pattern string) sortedSearchIdentifiers {
	if !strings.Contains(pattern, "*") {
		// No wildcards? This is just a find.
		x := ssi.find(pattern)
		if x == nil {
			return nil
		}
		return sortedSearchIdentifiers{x}
	}

	sb := new(strings.Builder)
	sb.WriteString("^")
	for {
		i := strings.Index(pattern, "*")
		if i == -1 {
			appendQuoteMeta(sb, pattern)
			break
		}
		appendQuoteMeta(sb, pattern[:i])
		sb.WriteString(".*")
		pattern = pattern[i+len("*"):]
	}
	sb.WriteString("$")
	pat := regexp.MustCompile(sb.String())

	result := make(sortedSearchIdentifiers, 0, len(ssi))
	for _, x := range ssi {
		if pat.MatchString(x.Name) {
			result = append(result, x)
		}
	}
	return result
}

func compareNamedExpr(y *NamedExpr, name string) int {
	return cmp.Compare(y.Name, name)
}

// appendQuoteMeta is the equivalent of sb.WriteString(regexp.QuoteMeta(s)),
// but reduces allocations.
func appendQuoteMeta(sb *strings.Builder, s string) {
	n := len(s)
	for _, c := range []byte(s) {
		if isRegexpSpecial(c) {
			n++
		}
	}

	sb.Grow(n)
	for _, c := range []byte(s) {
		if isRegexpSpecial(c) {
			sb.WriteByte('\\')
		}
		sb.WriteByte(c)
	}
}

func isRegexpSpecial(c byte) bool {
	return strings.IndexByte(`\.+*?()|[]{}^$`, c) != -1
}

func windashpermute(input string) []string {
	stringSet := map[string]struct{}{}
	windowsParamDashes := []string{"-", "/", EnDash, EmDash, HorizontalBar}

	for _, dash := range windowsParamDashes {
		transformed := WinDashMatcher.ReplaceAllLiteralString(input, dash)
		stringSet[transformed] = struct{}{}
	}
	return slices.Collect(maps.Keys(stringSet))
}
func base64permute(input string) []string {
	if len(input) == 0 {
		return []string{}
	}
	permutations := make([]string, 0, 3)
	inputBytes := []byte(input)

	for i := range 3 {
		shifted := bytes.Repeat([]byte(" "), i)
		shifted = append(shifted, inputBytes...)
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(shifted)))
		base64.StdEncoding.Encode(encoded, shifted)
		startOffset := []int{0, 2, 3}[i]
		endOffset := []int{0, -3, -2}[(len(inputBytes)+i)%3]
		encoded = encoded[startOffset : len(encoded)+endOffset]
		permutations = append(permutations, string(encoded))
	}

	return permutations
}
