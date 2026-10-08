// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"github.com/eclipse-biscuit/biscuit-go/v2"
)

type Comment string

func (c *Comment) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("parser: invalid comment values")
	}
	if !strings.HasPrefix(values[0], "//") {
		return errors.New("parser: invalid comment prefix")
	}
	*c = Comment(strings.TrimSpace(strings.TrimPrefix(values[0], "//")))
	return nil
}

type Variable string

func (v *Variable) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("parser: invalid variable values")
	}
	if !strings.HasPrefix(values[0], "$") {
		return errors.New("parser: invalid variable prefix")
	}
	*v = Variable(strings.TrimPrefix(values[0], "$"))
	return nil
}

type Parameter string

// Integer is an int64 literal with an optional leading minus sign. The sign
// is a separate token, so "1 -2" is still a subtraction, and the full text
// is parsed so that the smallest int64 is accepted.
type Integer int64

func (i *Integer) Capture(values []string) error {
	v, err := strconv.ParseInt(strings.Join(values, ""), 10, 64)
	if err != nil {
		return err
	}
	*i = Integer(v)
	return nil
}

type Bool bool

func (b *Bool) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("parser: invalid bool values")
	}
	v, err := strconv.ParseBool(values[0])
	if err != nil {
		return err
	}
	*b = Bool(v)
	return nil
}

type Block struct {
	Comments []*Comment      `@Comment*`
	Body     []*BlockElement `(@@ ";")*`
}

type BlockElement struct {
	Check      *Check         `@@`
	Scopes     []*ScopeElem   `| "trusting" @@ ("," @@)*`
	Predicate  *Predicate     `| @@`
	RuleBody   []*RuleElement `("<-" @@ ("," @@)*)?`
	RuleScopes []*ScopeElem   `("trusting" @@ ("," @@)*)?`
}

// ScopeElem is one entry of a `trusting` clause.
type ScopeElem struct {
	Authority bool    `@"authority"`
	Previous  bool    `| @"previous"`
	PublicKey *string `| @PublicKey`
}

func (s *ScopeElem) ToBiscuit() (biscuit.Scope, error) {
	switch {
	case s.Authority:
		return biscuit.Scope{Kind: biscuit.ScopeAuthority}, nil
	case s.Previous:
		return biscuit.Scope{Kind: biscuit.ScopePrevious}, nil
	case s.PublicKey != nil:
		key, err := biscuit.ParsePublicKey(*s.PublicKey)
		if err != nil {
			return biscuit.Scope{}, fmt.Errorf("parser: %w", err)
		}
		return biscuit.Scope{Kind: biscuit.ScopePublicKey, PublicKey: key}, nil
	default:
		return biscuit.Scope{}, errors.New("parser: empty scope")
	}
}

func scopesToBiscuit(elems []*ScopeElem) ([]biscuit.Scope, error) {
	if len(elems) == 0 {
		return nil, nil
	}
	scopes := make([]biscuit.Scope, len(elems))
	for i, e := range elems {
		s, err := e.ToBiscuit()
		if err != nil {
			return nil, err
		}
		scopes[i] = s
	}
	return scopes, nil
}

type ParametersMap map[string]biscuit.Term

func (b *Block) ToBiscuit(parameters ParametersMap) (*biscuit.ParsedBlock, error) {
	facts := []biscuit.Fact{}
	rules := []biscuit.Rule{}
	checks := []biscuit.Check{}
	var scopes []biscuit.Scope
	for _, e := range b.Body {
		if e.Check != nil {
			c, err := e.Check.ToBiscuit(parameters)
			if err != nil {
				return nil, err
			}
			checks = append(checks, *c)
		} else if e.Scopes != nil {
			s, err := scopesToBiscuit(e.Scopes)
			if err != nil {
				return nil, err
			}
			scopes = append(scopes, s...)
		} else if e.Predicate != nil && e.RuleBody != nil {
			rule := Rule{
				Head:   e.Predicate,
				Body:   e.RuleBody,
				Scopes: e.RuleScopes,
			}
			r, err := rule.ToBiscuit(parameters)
			if err != nil {
				return nil, err
			}
			rules = append(rules, *r)
		} else {
			p, err := e.Predicate.ToBiscuit(parameters)
			if err != nil {
				return nil, err
			}
			facts = append(facts, biscuit.Fact{Predicate: *p})
		}
	}
	return &biscuit.ParsedBlock{Facts: facts, Rules: rules, Checks: checks, Scopes: scopes}, nil
}

type Authorizer struct {
	Comments []*Comment           `@Comment*`
	Body     []*AuthorizerElement `(@@ ";")*`
}

type AuthorizerElement struct {
	Policy       *Policy       `@@`
	BlockElement *BlockElement `|@@`
}

func (b *Authorizer) ToBiscuit(parameters ParametersMap) (*biscuit.ParsedAuthorizer, error) {
	facts := []biscuit.Fact{}
	rules := []biscuit.Rule{}
	checks := []biscuit.Check{}
	policies := []biscuit.Policy{}
	var scopes []biscuit.Scope

	for _, e := range b.Body {
		if e.BlockElement != nil {
			be := e.BlockElement
			if be.Check != nil {
				c, err := be.Check.ToBiscuit(parameters)
				if err != nil {
					return nil, err
				}
				checks = append(checks, *c)
			} else if be.Scopes != nil {
				s, err := scopesToBiscuit(be.Scopes)
				if err != nil {
					return nil, err
				}
				scopes = append(scopes, s...)
			} else if be.Predicate != nil && be.RuleBody != nil {
				rule := Rule{
					Head:   be.Predicate,
					Body:   be.RuleBody,
					Scopes: be.RuleScopes,
				}
				r, err := rule.ToBiscuit(parameters)
				if err != nil {
					return nil, err
				}
				rules = append(rules, *r)
			} else {
				p, err := be.Predicate.ToBiscuit(parameters)
				if err != nil {
					return nil, err
				}
				facts = append(facts, biscuit.Fact{Predicate: *p})
			}
		} else if e.Policy != nil {
			p, err := e.Policy.ToBiscuit(parameters)
			if err != nil {
				return nil, err
			}
			policies = append(policies, *p)

		}
	}
	return &biscuit.ParsedAuthorizer{
		Policies: policies,
		Block:    biscuit.ParsedBlock{Facts: facts, Rules: rules, Checks: checks, Scopes: scopes},
	}, nil
}

type Rule struct {
	Comments []*Comment     `@Comment*`
	Head     *Predicate     `@@`
	Body     []*RuleElement `"<-" @@ ("," @@)*`
	Scopes   []*ScopeElem   `("trusting" @@ ("," @@)*)?`
}

type RuleElement struct {
	Predicate  *Predicate  `@@`
	Expression *Expression `|@@`
}

type Predicate struct {
	Name *string `@Ident`
	IDs  []*Term `"(" (@@ ("," @@)*)? ")"`
}

type CheckKind biscuit.CheckKind

func (k *CheckKind) Capture(values []string) error {
	switch strings.Join(values, " ") {
	case "check if":
		*k = CheckKind(biscuit.CheckKindOne)
	case "check all":
		*k = CheckKind(biscuit.CheckKindAll)
	case "reject if":
		*k = CheckKind(biscuit.CheckKindReject)
	default:
		return fmt.Errorf("parser: invalid check kind %q", values)
	}
	return nil
}

type Check struct {
	Kind    CheckKind     `@("check if" | "check all" | "reject if")`
	Queries []*CheckQuery `@@ ( "or" @@ )*`
}

type CheckQuery struct {
	Body   []*RuleElement `@@ ("," @@)*`
	Scopes []*ScopeElem   `("trusting" @@ ("," @@)*)?`
}

type Policy struct {
	Allow *Allow `@@`
	Deny  *Deny  `|@@`
}

type Allow struct {
	Queries []*CheckQuery `"allow if" @@ ( "or" @@ )*`
}

type Deny struct {
	Queries []*CheckQuery `"deny if" @@ ( "or" @@ )*`
}

// Braces hold a parameter {name}, the empty set {,}, the empty map {}, a set
// {a, b} or a map {k: v}; brackets hold an array [a, b].
type Term struct {
	Parameter  *Parameter `"{" @Ident "}"`
	Variable   *Variable  `| @Variable`
	Bytes      *HexString `| @@`
	String     *string    `| @String`
	Date       *string    `| @DateTime`
	Integer    *Integer   `| @("-"? Int)`
	Bool       *Bool      `| @Bool`
	Null       bool       `| @"null"`
	Braces     *Braces    `| @@`
	EmptyArray bool       `| @("[" "]")`
	Array      []*Term    `| "[" @@ ("," @@)* "]"`
}

// Braces is a set or a map: entries with a value make a map, entries
// without make a set. {,} is the empty set and {} the empty map.
type Braces struct {
	EmptySet bool          `"{" ( @("," "}")`
	EmptyMap bool          `| @"}"`
	Entries  []*BraceEntry `| @@ ("," @@)* "}" )`
}

type BraceEntry struct {
	Key   *Term `@@`
	Value *Term `(":" @@)?`
}

func (b *Braces) ToBiscuit(parameters ParametersMap) (biscuit.Term, error) {
	switch {
	case b.EmptySet:
		return biscuit.Set{}, nil
	case b.EmptyMap:
		return biscuit.Map{}, nil
	}

	isMap := b.Entries[0].Value != nil
	if isMap {
		m := make(biscuit.Map, 0, len(b.Entries))
		for _, e := range b.Entries {
			if e.Value == nil {
				return nil, errors.New("parser: map entry without a value")
			}
			key, err := e.Key.ToBiscuit(parameters)
			if err != nil {
				return nil, err
			}
			switch key.Type() {
			case biscuit.TermTypeInteger, biscuit.TermTypeString:
			default:
				return nil, fmt.Errorf("parser: map key must be an integer or a string, got %s", key)
			}
			value, err := e.Value.ToBiscuit(parameters)
			if err != nil {
				return nil, err
			}
			if value.Type() == biscuit.TermTypeVariable {
				return nil, errors.New("parser: a map cannot contain variables")
			}
			m = append(m, biscuit.MapEntry{Key: key, Value: value})
		}
		return m, nil
	}

	set := make(biscuit.Set, 0, len(b.Entries))
	for _, e := range b.Entries {
		if e.Value != nil {
			return nil, errors.New("parser: set element with a value")
		}
		elt, err := e.Key.ToBiscuit(parameters)
		if err != nil {
			return nil, err
		}
		if elt.Type() == biscuit.TermTypeVariable {
			return nil, ErrVariableInSet
		}
		set = append(set, elt)
	}
	return set, nil
}

type Operator int

const (
	OpMul Operator = iota
	OpDiv
	OpAdd
	OpSub
	OpAnd
	OpOr
	OpLessOrEqual
	OpGreaterOrEqual
	OpLessThan
	OpGreaterThan
	OpEqual
	OpContains
	OpPrefix
	OpSuffix
	OpMatches
	OpIntersection
	OpUnion
	OpLength
	OpNegate
	OpNotEqual
	OpBitwiseAnd
	OpBitwiseOr
	OpBitwiseXor
	OpHeterogeneousEqual
	OpHeterogeneousNotEqual
	OpLazyAnd
	OpLazyOr
	OpAll
	OpAny
	OpGet
	OpTypeOf
)

var operatorMap = map[string]Operator{
	"+": OpAdd,
	"-": OpSub, "*": OpMul, "/": OpDiv, "&&": OpLazyAnd, "||": OpLazyOr, "all": OpAll, "any": OpAny, "get": OpGet, "<=": OpLessOrEqual, ">=": OpGreaterOrEqual, "<": OpLessThan, ">": OpGreaterThan,
	"==": OpHeterogeneousEqual, "===": OpEqual, "!=": OpHeterogeneousNotEqual, "!==": OpNotEqual, "&": OpBitwiseAnd, "|": OpBitwiseOr, "^": OpBitwiseXor, "!": OpNegate, "contains": OpContains, "starts_with": OpPrefix, "ends_with": OpSuffix, "matches": OpMatches, "intersection": OpIntersection, "union": OpUnion, "length": OpLength, "type": OpTypeOf}

func (o *Operator) Capture(s []string) error {
	*o = operatorMap[s[0]]
	return nil
}

type Expression struct {
	Left  *Expr1     `@@`
	Right []*OpExpr1 `@@*`
}

type OpExpr1 struct {
	Operator Operator `@("||")`
	Expr1    *Expr1   `@@`
}

type Expr1 struct {
	Left  *Expr2     `@@`
	Right []*OpExpr2 `@@*`
}

type OpExpr2 struct {
	Operator Operator `@("&&")`
	Expr2    *Expr2   `@@`
}

type Expr2 struct {
	Left  *ExprXor `@@`
	Right *OpExpr3 `@@?`
}

type OpExpr3 struct {
	Operator Operator `@("<=" | ">=" | "<" | ">" | "===" | "==" | "!==" | "!=")`
	Expr3    *ExprXor `@@`
}

// Bitwise operators sit between comparisons and arithmetic, in the order of
// the spec: ^ binds loosest, then |, then &.
type ExprXor struct {
	Left  *ExprBitOr   `@@`
	Right []*OpExprXor `@@*`
}

type OpExprXor struct {
	Operator Operator   `@("^")`
	Expr     *ExprBitOr `@@`
}

type ExprBitOr struct {
	Left  *ExprBitAnd    `@@`
	Right []*OpExprBitOr `@@*`
}

type OpExprBitOr struct {
	Operator Operator    `@("|")`
	Expr     *ExprBitAnd `@@`
}

type ExprBitAnd struct {
	Left  *Expr3          `@@`
	Right []*OpExprBitAnd `@@*`
}

type OpExprBitAnd struct {
	Operator Operator `@("&")`
	Expr     *Expr3   `@@`
}

type Expr3 struct {
	Left  *Expr4     `@@`
	Right []*OpExpr4 `@@*`
}

type OpExpr4 struct {
	Operator Operator `@("+" | "-")`
	Expr4    *Expr4   `@@`
}

type Expr4 struct {
	Left  *Expr5     `@@`
	Right []*OpExpr5 `@@*`
}

type OpExpr5 struct {
	Operator Operator `@("*" | "/")`
	Expr5    *Expr5   `@@`
}

type Expr5 struct {
	Operator *Operator `@("!")?`
	Expr6    *Expr6    `@@`
}

type Expr6 struct {
	Left  *ExprTerm  `@@`
	Right []*OpExpr7 `@@*`
}

type OpExpr7 struct {
	Operator   Operator    `Dot (@("matches" | "starts_with" | "ends_with" | "contains" | "union" | "intersection" | "length" | "all" | "any" | "get" | "type")`
	Extern     string      `| @Ident)`
	Closure    *ClosureArg `"(" (@@`
	Expression *Expression `| @@)? ")"`
}

const externPrefix = "extern::"

// ClosureArg is the `$p -> body` argument of .all() and .any().
type ClosureArg struct {
	Param *Variable   `@Variable ClosureArrow`
	Body  *Expression `@@`
}

type ExprTerm struct {
	Term       *Term       `@@`
	Expression *Expression `| "(" @@? ")"`
}

func (e *Expression) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	if err := e.Left.ToExpr(expr, parameters); err != nil {
		return err
	}

	for _, op := range e.Right {
		if err := op.ToExpr(expr, parameters); err != nil {
			return err
		}
	}
	return nil
}

func (e *Expr1) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	if err := e.Left.ToExpr(expr, parameters); err != nil {
		return err
	}

	for _, op := range e.Right {
		if err := op.ToExpr(expr, parameters); err != nil {
			return err
		}
	}
	return nil
}

func (e *Expr2) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	if err := e.Left.ToExpr(expr, parameters); err != nil {
		return err
	}
	if e.Right != nil {
		return e.Right.ToExpr(expr, parameters)
	}
	return nil
}

func (e *ExprXor) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	if err := e.Left.ToExpr(expr, parameters); err != nil {
		return err
	}
	for _, op := range e.Right {
		if err := op.Expr.ToExpr(expr, parameters); err != nil {
			return err
		}
		if err := op.Operator.ToExpr(expr); err != nil {
			return err
		}
	}
	return nil
}

func (e *ExprBitOr) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	if err := e.Left.ToExpr(expr, parameters); err != nil {
		return err
	}
	for _, op := range e.Right {
		if err := op.Expr.ToExpr(expr, parameters); err != nil {
			return err
		}
		if err := op.Operator.ToExpr(expr); err != nil {
			return err
		}
	}
	return nil
}

func (e *ExprBitAnd) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	if err := e.Left.ToExpr(expr, parameters); err != nil {
		return err
	}
	for _, op := range e.Right {
		if err := op.Expr.ToExpr(expr, parameters); err != nil {
			return err
		}
		if err := op.Operator.ToExpr(expr); err != nil {
			return err
		}
	}
	return nil
}

func (e *Expr3) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	if err := e.Left.ToExpr(expr, parameters); err != nil {
		return err
	}

	for _, op := range e.Right {
		if err := op.ToExpr(expr, parameters); err != nil {
			return err
		}
	}
	return nil
}

func (e *Expr4) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	if err := e.Left.ToExpr(expr, parameters); err != nil {
		return err
	}

	for _, op := range e.Right {
		if err := op.ToExpr(expr, parameters); err != nil {
			return err
		}
	}
	return nil
}

func (e *Expr5) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	if err := e.Expr6.ToExpr(expr, parameters); err != nil {
		return err
	}
	if e.Operator != nil {
		*expr = append(*expr, biscuit.UnaryNegate)
	}
	return nil
}

func (e *Expr6) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	if err := e.Left.ToExpr(expr, parameters); err != nil {
		return err
	}
	for _, op := range e.Right {
		if err := op.ToExpr(expr, parameters); err != nil {
			return err
		}
	}
	return nil
}

func (e *ExprTerm) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	switch {
	case e.Term != nil:
		term, err := e.Term.ToBiscuit(parameters)
		if err != nil {
			return err
		}
		*expr = append(*expr, biscuit.Value{Term: term})
	case e.Expression != nil:
		if err := e.Expression.ToExpr(expr, parameters); err != nil {
			return err
		}
		*expr = append(*expr, biscuit.UnaryParens)
	}
	return nil
}

// && and || evaluate their right side only when needed: it is emitted as a
// closure without parameters (datalog v3.3).
func (e *OpExpr1) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	var right biscuit.Expression
	if err := e.Expr1.ToExpr(&right, parameters); err != nil {
		return err
	}
	*expr = append(*expr, biscuit.Closure{Body: right})
	return e.Operator.ToExpr(expr)
}

func (e *OpExpr2) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	var right biscuit.Expression
	if err := e.Expr2.ToExpr(&right, parameters); err != nil {
		return err
	}
	*expr = append(*expr, biscuit.Closure{Body: right})
	return e.Operator.ToExpr(expr)
}

func (e *OpExpr3) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	if err := e.Expr3.ToExpr(expr, parameters); err != nil {
		return err
	}
	return e.Operator.ToExpr(expr)
}

func (e *OpExpr4) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	if err := e.Expr4.ToExpr(expr, parameters); err != nil {
		return err
	}
	return e.Operator.ToExpr(expr)
}

func (e *OpExpr5) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	if err := e.Expr5.ToExpr(expr, parameters); err != nil {
		return err
	}
	return e.Operator.ToExpr(expr)
}

func (e *OpExpr7) ToExpr(expr *biscuit.Expression, parameters ParametersMap) error {
	if e.Extern != "" {
		name := strings.TrimPrefix(e.Extern, externPrefix)
		if name == "" || name == e.Extern {
			return fmt.Errorf("parser: unknown method .%s()", e.Extern)
		}
		if e.Closure != nil {
			return fmt.Errorf("parser: .%s() does not take a closure", e.Extern)
		}
		if e.Expression == nil {
			*expr = append(*expr, biscuit.ExternUnary{Name: name})
			return nil
		}
		if err := e.Expression.ToExpr(expr, parameters); err != nil {
			return err
		}
		*expr = append(*expr, biscuit.ExternBinary{Name: name})
		return nil
	}
	switch {
	case e.Closure != nil:
		var body biscuit.Expression
		if err := e.Closure.Body.ToExpr(&body, parameters); err != nil {
			return err
		}
		*expr = append(*expr, biscuit.Closure{Params: []biscuit.Variable{biscuit.Variable(*e.Closure.Param)}, Body: body})
	case e.Expression != nil:
		if err := e.Expression.ToExpr(expr, parameters); err != nil {
			return err
		}
	}
	return e.Operator.ToExpr(expr)
}

func (op *Operator) ToExpr(expr *biscuit.Expression) error {
	var biscuit_op biscuit.Op
	switch *op {
	case OpAnd:
		biscuit_op = biscuit.BinaryAnd
	case OpOr:
		biscuit_op = biscuit.BinaryOr
	case OpMul:
		biscuit_op = biscuit.BinaryMul
	case OpDiv:
		biscuit_op = biscuit.BinaryDiv
	case OpAdd:
		biscuit_op = biscuit.BinaryAdd
	case OpSub:
		biscuit_op = biscuit.BinarySub
	case OpLessOrEqual:
		biscuit_op = biscuit.BinaryLessOrEqual
	case OpGreaterOrEqual:
		biscuit_op = biscuit.BinaryGreaterOrEqual
	case OpLessThan:
		biscuit_op = biscuit.BinaryLessThan
	case OpGreaterThan:
		biscuit_op = biscuit.BinaryGreaterThan
	case OpEqual:
		biscuit_op = biscuit.BinaryEqual
	case OpNotEqual:
		biscuit_op = biscuit.BinaryNotEqual
	case OpHeterogeneousEqual:
		biscuit_op = biscuit.BinaryHeterogeneousEqual
	case OpHeterogeneousNotEqual:
		biscuit_op = biscuit.BinaryHeterogeneousNotEqual
	case OpLazyAnd:
		biscuit_op = biscuit.BinaryLazyAnd
	case OpLazyOr:
		biscuit_op = biscuit.BinaryLazyOr
	case OpAll:
		biscuit_op = biscuit.BinaryAll
	case OpAny:
		biscuit_op = biscuit.BinaryAny
	case OpGet:
		biscuit_op = biscuit.BinaryGet
	case OpBitwiseAnd:
		biscuit_op = biscuit.BinaryBitwiseAnd
	case OpBitwiseOr:
		biscuit_op = biscuit.BinaryBitwiseOr
	case OpBitwiseXor:
		biscuit_op = biscuit.BinaryBitwiseXor
	case OpContains:
		biscuit_op = biscuit.BinaryContains
	case OpPrefix:
		biscuit_op = biscuit.BinaryPrefix
	case OpSuffix:
		biscuit_op = biscuit.BinarySuffix
	case OpMatches:
		biscuit_op = biscuit.BinaryRegex
	case OpLength:
		biscuit_op = biscuit.UnaryLength
	case OpTypeOf:
		biscuit_op = biscuit.UnaryTypeOf
	case OpIntersection:
		biscuit_op = biscuit.BinaryIntersection
	case OpUnion:
		biscuit_op = biscuit.BinaryUnion
	default:
		return fmt.Errorf("parser: unsupported operator %d", *op)
	}

	*expr = append(*expr, biscuit_op)
	return nil
}

type HexString string

func (h *HexString) Parse(lex *lexer.PeekingLexer) error {
	token := lex.Peek()
	if !strings.HasPrefix(token.Value, "hex:") {
		return participle.NextMatch
	}
	lex.Next()
	*h = HexString(token.Value[4:])
	return nil
}

func (h *HexString) Decode() ([]byte, error) {
	return hex.DecodeString(string(*h))
}

func (h *HexString) String() string {
	return string(*h)
}

func (p *Predicate) ToBiscuit(parameters ParametersMap) (*biscuit.Predicate, error) {
	terms := make([]biscuit.Term, 0, len(p.IDs))
	for _, a := range p.IDs {
		biscuitTerm, err := a.ToBiscuit(parameters)
		if err != nil {
			return nil, err
		}
		terms = append(terms, biscuitTerm)
	}

	return &biscuit.Predicate{
		Name: *p.Name,
		IDs:  terms,
	}, nil
}

func (a *Term) ToBiscuit(parameters ParametersMap) (biscuit.Term, error) {
	var biscuitTerm biscuit.Term
	switch {
	case a.Integer != nil:
		biscuitTerm = biscuit.Integer(*a.Integer)
	case a.String != nil:
		biscuitTerm = biscuit.String(*a.String)
	case a.Variable != nil:
		biscuitTerm = biscuit.Variable(*a.Variable)
	case a.Date != nil:
		date, err := time.Parse(time.RFC3339, *a.Date)
		if err != nil {
			return nil, fmt.Errorf("parser: failed to decode date: %v", err)
		}

		biscuitTerm = biscuit.Date(date)
	case a.Bytes != nil:
		b, err := a.Bytes.Decode()
		if err != nil {
			return nil, fmt.Errorf("parser: failed to decode hex string: %v", err)
		}
		biscuitTerm = biscuit.Bytes(b)
	case a.Bool != nil:
		biscuitTerm = biscuit.Bool(*a.Bool)
	case a.Null:
		biscuitTerm = biscuit.Null{}
	case a.Braces != nil:
		t, err := a.Braces.ToBiscuit(parameters)
		if err != nil {
			return nil, err
		}
		biscuitTerm = t
	case a.EmptyArray:
		biscuitTerm = biscuit.Array{}
	case a.Array != nil:
		array := make(biscuit.Array, 0, len(a.Array))
		for _, term := range a.Array {
			elt, err := term.ToBiscuit(parameters)
			if err != nil {
				return nil, err
			}
			if elt.Type() == biscuit.TermTypeVariable {
				return nil, errors.New("parser: an array cannot contain variables")
			}
			array = append(array, elt)
		}
		biscuitTerm = array
	case a.Parameter != nil:
		paramName := string(*(a.Parameter))
		paramValue := parameters[paramName]
		if paramValue == nil {
			return nil, fmt.Errorf("parser: unbound parameter: %s", paramName)
		}
		biscuitTerm = paramValue

	default:
		return nil, errors.New("parser: unsupported predicate, must be one of integer, string, variable, or bytes")
	}

	return biscuitTerm, nil
}

func (r *Rule) ToBiscuit(parameters ParametersMap) (*biscuit.Rule, error) {
	body := []biscuit.Predicate{}
	expressions := make([]biscuit.Expression, 0)

	for _, p := range r.Body {
		switch {
		case p.Predicate != nil:
			{
				predicate, err := (*p.Predicate).ToBiscuit(parameters)
				if err != nil {
					return nil, err
				}
				body = append(body, *predicate)
			}
		case p.Expression != nil:
			{
				var expr biscuit.Expression
				if err := (*p.Expression).ToExpr(&expr, parameters); err != nil {
					return nil, err
				}

				expressions = append(expressions, expr)
			}
		}
	}

	head, err := r.Head.ToBiscuit(parameters)
	if err != nil {
		return nil, err
	}

	scopes, err := scopesToBiscuit(r.Scopes)
	if err != nil {
		return nil, err
	}

	return &biscuit.Rule{
		Head:        *head,
		Body:        body,
		Expressions: expressions,
		Scopes:      scopes,
	}, nil
}

func (c *Check) ToBiscuit(parameters ParametersMap) (*biscuit.Check, error) {
	queries := make([]biscuit.Rule, 0, len(c.Queries))
	for _, q := range c.Queries {
		r, err := q.ToBiscuit(parameters)
		if err != nil {
			return nil, err
		}

		queries = append(queries, *r)
	}

	return &biscuit.Check{
		Queries: queries,
		Kind:    biscuit.CheckKind(c.Kind),
	}, nil
}

func (r *CheckQuery) ToBiscuit(parameters ParametersMap) (*biscuit.Rule, error) {
	body := []biscuit.Predicate{}
	expressions := make([]biscuit.Expression, 0)

	for _, p := range r.Body {
		switch {
		case p.Predicate != nil:
			{
				predicate, err := (*p.Predicate).ToBiscuit(parameters)
				if err != nil {
					return nil, err
				}
				body = append(body, *predicate)
			}
		case p.Expression != nil:
			{
				var expr biscuit.Expression
				if err := (*p.Expression).ToExpr(&expr, parameters); err != nil {
					return nil, err
				}

				expressions = append(expressions, expr)
			}
		}
	}

	head := &biscuit.Predicate{
		Name: "query",
		IDs:  []biscuit.Term{},
	}

	scopes, err := scopesToBiscuit(r.Scopes)
	if err != nil {
		return nil, err
	}

	return &biscuit.Rule{
		Head:        *head,
		Body:        body,
		Expressions: expressions,
		Scopes:      scopes,
	}, nil
}

func (p *Policy) ToBiscuit(parameters ParametersMap) (*biscuit.Policy, error) {
	var parsedQueries []*CheckQuery
	var kind biscuit.PolicyKind
	switch {
	case p.Allow != nil:
		{
			parsedQueries = p.Allow.Queries
			kind = biscuit.PolicyKindAllow
			break
		}
	case p.Deny != nil:
		{
			parsedQueries = p.Deny.Queries
			kind = biscuit.PolicyKindDeny
			break
		}
	}
	queries := make([]biscuit.Rule, 0, len(parsedQueries))
	for _, q := range parsedQueries {
		r, err := q.ToBiscuit(parameters)
		if err != nil {
			return nil, err
		}

		queries = append(queries, *r)
	}

	return &biscuit.Policy{
		Queries: queries,
		Kind:    kind,
	}, nil
}
