package parser

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/datalog"
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

type Symbol string

func (s *Symbol) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("parser: invalid symbol values")
	}
	if !strings.HasPrefix(values[0], "#") {
		return errors.New("parser: invalid symbol prefix")
	}
	*s = Symbol(strings.TrimPrefix(values[0], "#"))
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

type Rule struct {
	Comments    []*Comment    `@Comment*`
	Head        *Predicate    `@@`
	Body        []*Predicate  `"<-" @@ ("," @@)*`
	Constraints []*Constraint `("@" @@ ("," @@)*)*`
}

type Predicate struct {
	Name *string `@Ident`
	IDs  []*Term `"(" (@@ ("," @@)*)* ")"`
}

type Caveat struct {
	Queries []*Rule `"[" @@ ( "||" @@ )* "]"`
}

type Term struct {
	Symbol   *Symbol    `@Symbol`
	Variable *Variable  `| @Variable`
	Bytes    *HexString `| @@`
	String   *string    `| @String`
	Integer  *int64     `| @Int`
	Bool     *Bool      `| @Bool`
	Set      []*Term    `| "[" @@ ("," @@)* "]"`
}

type Constraint struct {
	VariableConstraint *VariableConstraint `@@`
	FunctionConstraint *FunctionConstraint `| @@`
}

type VariableConstraint struct {
	Variable *Variable         `@Variable`
	Date     *DateComparison   `((@@`
	Bytes    *BytesComparison  `| @@`
	String   *StringComparison `| @@`
	Int      *IntComparison    `| @@)`
	Set      *Set              `| @@)`
}

type FunctionConstraint struct {
	Function *string   `@Function "("`
	Variable *Variable `@Variable ","`
	Argument *string   `@String ")"`
}

type IntComparison struct {
	Operation *string `@("=="|">="|"<="|">"|"<")`
	Target    *int64  `@Int`
}

type StringComparison struct {
	Operation *string `@("==")`
	Target    *string `@String`
}

type BytesComparison struct {
	Operation *string    `@("==")`
	Target    *HexString `@@`
}

type DateComparison struct {
	Operation *string `@("<" | ">")`
	Target    *string `@String`
}

type Set struct {
	Not     bool        `@"not"? "in"`
	Symbols []Symbol    `("[" ( @Symbol ("," @Symbol)*)+ "]"`
	Bytes   []HexString `| "[" ( @@ ("," @@)*)+ "]"`
	String  []string    `| "[" (@String ("," @String)*)+ "]"`
	Int     []int64     `| "[" (@Int ("," @Int)*)+ "]")`
}

type HexString string

func (h *HexString) Parse(lex *lexer.PeekingLexer) error {
	token, err := lex.Peek(0)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(token.Value, "hex:") {
		return participle.NextMatch
	}

	_, err = lex.Next()
	if err != nil {
		return err
	}

	*h = HexString(strings.TrimPrefix(token.Value, "hex:"))

	return nil
}

func (h *HexString) Decode() ([]byte, error) {
	return hex.DecodeString(string(*h))
}

func (h *HexString) String() string {
	return string(*h)
}

func (p *Predicate) ToBiscuit() (*biscuit.Predicate, error) {
	terms := make([]biscuit.Term, 0, len(p.IDs))
	for _, a := range p.IDs {
		biscuitTerm, err := a.ToBiscuit()
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

func (a *Term) ToBiscuit() (biscuit.Term, error) {
	var biscuitTerm biscuit.Term
	switch {
	case a.Integer != nil:
		biscuitTerm = biscuit.Integer(*a.Integer)
	case a.String != nil:
		biscuitTerm = biscuit.String(*a.String)
	case a.Symbol != nil:
		biscuitTerm = biscuit.Symbol(*a.Symbol)
	case a.Variable != nil:
		biscuitTerm = biscuit.Variable(*a.Variable)
	case a.Bytes != nil:
		b, err := a.Bytes.Decode()
		if err != nil {
			return nil, fmt.Errorf("parser: failed to decode hex string: %v", err)
		}
		biscuitTerm = biscuit.Bytes(b)
	case a.Bool != nil:
		biscuitTerm = biscuit.Bool(*a.Bool)
	case a.Set != nil:
		biscuitSet := make(biscuit.Set, 0, len(a.Set))
		for _, term := range a.Set {
			setTerm, err := term.ToBiscuit()
			if err != nil {
				return nil, err
			}
			if setTerm.Type() == biscuit.TermTypeVariable {
				return nil, ErrVariableInSet
			}
			biscuitSet = append(biscuitSet, setTerm)
		}
		biscuitTerm = biscuitSet
	default:
		return nil, errors.New("parser: unsupported predicate, must be one of integer, string, symbol, variable, or bytes")
	}

	return biscuitTerm, nil
}

func (c *Constraint) ToBiscuit() (*biscuit.Constraint, error) {
	var constraint *biscuit.Constraint
	var err error

	switch {
	case c.VariableConstraint != nil:
		constraint, err = c.VariableConstraint.ToBiscuit()
	case c.FunctionConstraint != nil:
		constraint, err = c.FunctionConstraint.ToBiscuit()
	default:
		err = errors.New("parser: unsupported constraint, must be one of variable or function")
	}

	if err != nil {
		return nil, err
	}

	return constraint, nil
}

func (c *VariableConstraint) ToBiscuit() (*biscuit.Constraint, error) {
	constraint := &biscuit.Constraint{
		Name: biscuit.Variable(*c.Variable),
	}
	switch {
	case c.Date != nil:
		date, err := time.Parse(time.RFC3339, *c.Date.Target)
		if err != nil {
			return nil, err
		}
		switch *c.Date.Operation {
		case "<":
			constraint.Checker = biscuit.DateComparisonChecker{
				Comparison: datalog.DateComparisonBefore,
				Date:       biscuit.Date(date),
			}
		case ">":
			constraint.Checker = biscuit.DateComparisonChecker{
				Comparison: datalog.DateComparisonAfter,
				Date:       biscuit.Date(date),
			}
		default:
			return nil, fmt.Errorf("parser: unsupported date operation: %s", *c.Date.Operation)
		}
	case c.Int != nil:
		switch *c.Int.Operation {
		case "<":
			constraint.Checker = biscuit.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonLT,
				Integer:    biscuit.Integer(*c.Int.Target),
			}
		case "<=":
			constraint.Checker = biscuit.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonLTE,
				Integer:    biscuit.Integer(*c.Int.Target),
			}
		case "==":
			constraint.Checker = biscuit.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonEqual,
				Integer:    biscuit.Integer(*c.Int.Target),
			}
		case ">":
			constraint.Checker = biscuit.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonGT,
				Integer:    biscuit.Integer(*c.Int.Target),
			}
		case ">=":
			constraint.Checker = biscuit.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonGTE,
				Integer:    biscuit.Integer(*c.Int.Target),
			}
		default:
			return nil, fmt.Errorf("parser: unsupported int operation: %s", *c.Int.Operation)
		}
	case c.String != nil:
		constraint.Checker = biscuit.StringComparisonChecker{
			Comparison: datalog.StringComparisonEqual,
			Str:        biscuit.String(*c.String.Target),
		}
	case c.Bytes != nil:
		switch *c.Bytes.Operation {
		case "==":
			b, err := c.Bytes.Target.Decode()
			if err != nil {
				return nil, fmt.Errorf("parser: failed to decode hex string: %v", err)
			}
			constraint.Checker = biscuit.BytesComparisonChecker{
				Comparison: datalog.BytesComparisonEqual,
				Bytes:      biscuit.Bytes(b),
			}
		default:
			return nil, fmt.Errorf("parser: unsupported bytes operation: %s", *c.Bytes.Operation)
		}
	case c.Set != nil:
		switch {
		case c.Set.Symbols != nil:
			set := make(map[biscuit.Symbol]struct{}, len(c.Set.Symbols))
			for _, s := range c.Set.Symbols {
				set[biscuit.Symbol(s)] = struct{}{}
			}
			constraint.Checker = biscuit.SymbolInChecker{
				Set: set,
				Not: c.Set.Not,
			}
		case c.Set.Int != nil:
			set := make(map[biscuit.Integer]struct{}, len(c.Set.Int))
			for _, i := range c.Set.Int {
				set[biscuit.Integer(i)] = struct{}{}
			}
			constraint.Checker = biscuit.IntegerInChecker{
				Set: set,
				Not: c.Set.Not,
			}
		case c.Set.String != nil:
			set := make(map[biscuit.String]struct{}, len(c.Set.String))
			for _, s := range c.Set.String {
				set[biscuit.String(s)] = struct{}{}
			}
			constraint.Checker = biscuit.StringInChecker{
				Set: set,
				Not: c.Set.Not,
			}
		case c.Set.Bytes != nil:
			set := make(map[string]struct{}, len(c.Set.Bytes))
			for _, s := range c.Set.Bytes {
				b, err := s.Decode()
				if err != nil {
					return nil, fmt.Errorf("parser: failed to decode hex string: %v", err)
				}
				set[string(b)] = struct{}{}
			}

			constraint.Checker = biscuit.BytesInChecker{
				Set: set,
				Not: c.Set.Not,
			}
		default:
			return nil, errors.New("parser: unsupported set type, must be one of symbols, int, string, or bytes")
		}
	default:
		return nil, errors.New("parser: unsupported variable constraint, must be one of date, int, string, bytes, or set")
	}
	return constraint, nil
}

func (c *FunctionConstraint) ToBiscuit() (*biscuit.Constraint, error) {
	constraint := &biscuit.Constraint{
		Name: biscuit.Variable(*c.Variable),
	}
	switch *c.Function {
	case "prefix":
		constraint.Checker = biscuit.StringComparisonChecker{
			Comparison: datalog.StringComparisonPrefix,
			Str:        biscuit.String(*c.Argument),
		}
	case "suffix":
		constraint.Checker = biscuit.StringComparisonChecker{
			Comparison: datalog.StringComparisonSuffix,
			Str:        biscuit.String(*c.Argument),
		}
	case "match":
		re, err := regexp.Compile(*c.Argument)
		if err != nil {
			return nil, err
		}
		constraint.Checker = biscuit.StringRegexpChecker(*re)
	default:
		return nil, fmt.Errorf("parser: unsupported function: %s", *c.Function)
	}

	return constraint, nil
}

func (r *Rule) ToBiscuit() (*biscuit.Rule, error) {
	body := make([]biscuit.Predicate, len(r.Body))
	for i, p := range r.Body {
		b, err := p.ToBiscuit()
		if err != nil {
			return nil, err
		}
		body[i] = *b
	}

	constraints := make([]biscuit.Constraint, len(r.Constraints))
	for i, c := range r.Constraints {
		constraint, err := c.ToBiscuit()
		if err != nil {
			return nil, err
		}
		constraints[i] = *constraint
	}

	head, err := r.Head.ToBiscuit()
	if err != nil {
		return nil, err
	}

	return &biscuit.Rule{
		Head:        *head,
		Body:        body,
		Constraints: constraints,
	}, nil
}

func (c *Caveat) ToBiscuit() (*biscuit.Caveat, error) {
	queries := make([]biscuit.Rule, 0, len(c.Queries))
	for _, q := range c.Queries {
		r, err := q.ToBiscuit()
		if err != nil {
			return nil, err
		}

		queries = append(queries, *r)
	}

	return &biscuit.Caveat{
		Queries: queries,
	}, nil
}
