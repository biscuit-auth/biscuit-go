package parser

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/alecthomas/participle"
	"github.com/alecthomas/participle/lexer"
	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/datalog"
)

var (
	ErrVariableInFact = errors.New("parser: a fact cannot contain any variable")
)

var defaultParserOptions = []participle.Option{
	participle.Lexer(lexer.DefaultDefinition),
	participle.UseLookahead(3),
}

type Parser interface {
	Fact() FactParser
	Rule() RuleParser
	Caveat() CaveatParser
}

type FactParser interface {
	MustParse(fact string) biscuit.Fact
	Parse(fact string) (biscuit.Fact, error)
}

type RuleParser interface {
	MustParse(rule string) biscuit.Rule
	Parse(rule string) (biscuit.Rule, error)
}

type CaveatParser interface {
	MustParse(caveat string) biscuit.Caveat
	Parse(caveat string) (biscuit.Caveat, error)
}

type parser struct {
	factParser   FactParser
	ruleParser   RuleParser
	caveatParser CaveatParser
}

var _ Parser = (*parser)(nil)

func New() Parser {
	return &parser{
		factParser:   &factParser{participle.MustBuild(&Predicate{}, DefaultParserOptions...)},
		ruleParser:   &ruleParser{participle.MustBuild(&Rule{}, DefaultParserOptions...)},
		caveatParser: &caveatParser{participle.MustBuild(&Caveat{}, DefaultParserOptions...)},
	}
}

func (p *parser) Fact() FactParser {
	return p.factParser
}
func (p *parser) Rule() RuleParser {
	return p.ruleParser
}
func (p *parser) Caveat() CaveatParser {
	return p.caveatParser
}

type factParser struct {
	*participle.Parser
}

var _ FactParser = (*factParser)(nil)

func (p *factParser) MustParse(fact string) biscuit.Fact {
	f, err := p.Parse(fact)
	if err != nil {
		panic(err)
	}

	return f
}

func (p *factParser) Parse(fact string) (biscuit.Fact, error) {
	parsed := &Predicate{}
	if err := p.ParseString(fact, parsed); err != nil {
		return biscuit.Fact{}, err
	}

	pred, err := convertPredicate(parsed)
	if err != nil {
		return biscuit.Fact{}, err
	}

	for _, a := range pred.IDs {
		if a.Type() == biscuit.AtomTypeVariable {
			return biscuit.Fact{}, ErrVariableInFact
		}
	}

	return biscuit.Fact{Predicate: *pred}, nil
}

type ruleParser struct {
	*participle.Parser
}

var _ RuleParser = (*ruleParser)(nil)

func (p *ruleParser) MustParse(rule string) biscuit.Rule {
	r, err := p.Parse(rule)
	if err != nil {
		panic(err)
	}

	return r
}

func (p *ruleParser) Parse(rule string) (biscuit.Rule, error) {
	parsed := &Rule{}
	if err := p.ParseString(rule, parsed); err != nil {
		return biscuit.Rule{}, err
	}

	r, err := convertRule(parsed)
	if err != nil {
		return biscuit.Rule{}, err
	}

	return *r, nil
}

type caveatParser struct {
	*participle.Parser
}

var _ CaveatParser = (*caveatParser)(nil)

func (p *caveatParser) MustParse(caveat string) biscuit.Caveat {
	c, err := p.Parse(caveat)
	if err != nil {
		panic(err)
	}

	return c
}

func (p *caveatParser) Parse(caveat string) (biscuit.Caveat, error) {
	parsed := &Caveat{}
	if err := p.ParseString(caveat, parsed); err != nil {
		return biscuit.Caveat{}, err
	}

	queries := make([]biscuit.Rule, len(parsed.Queries))
	for i, q := range parsed.Queries {
		query, err := convertQuery(q)
		if err != nil {
			return biscuit.Caveat{}, err
		}

		queries[i] = *query
	}

	return biscuit.Caveat{
		Queries: queries,
	}, nil
}

func convertPredicate(p *Predicate) (*biscuit.Predicate, error) {
	var atoms []biscuit.Atom
	for _, a := range p.IDs {
		switch {
		case a.Integer != nil:
			atoms = append(atoms, biscuit.Integer(*a.Integer))
		case a.String != nil:
			atoms = append(atoms, biscuit.String(*a.String))
		case a.Symbol != nil:
			atoms = append(atoms, biscuit.Symbol(*a.Symbol))
		case a.Variable != nil:
			atoms = append(atoms, biscuit.Variable(*a.Variable))
		default:
			return nil, errors.New("parser: unsupported predicate, must be one of integer, string, symbol or variable")
		}
	}

	return &biscuit.Predicate{
		Name: p.Name,
		IDs:  atoms,
	}, nil
}

func convertConstraint(c *Constraint) (*biscuit.Constraint, error) {
	var constraint *biscuit.Constraint
	var err error

	switch {
	case c.VariableConstraint != nil:
		constraint, err = convertVariableConstraint(c.VariableConstraint)
	case c.FunctionConstraint != nil:
		constraint, err = convertFunctionConstraint(c.FunctionConstraint)
	default:
		err = errors.New("parser: unsupported constraint, must be one of variable or function")
	}

	if err != nil {
		return nil, err
	}

	return constraint, nil
}

func convertVariableConstraint(c *VariableConstraint) (*biscuit.Constraint, error) {
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
			set := make(map[biscuit.Integer]struct{}, len(c.Set.Symbols))
			for _, i := range c.Set.Int {
				set[biscuit.Integer(i)] = struct{}{}
			}
			constraint.Checker = biscuit.IntegerInChecker{
				Set: set,
				Not: c.Set.Not,
			}
		case c.Set.String != nil:
			set := make(map[biscuit.String]struct{}, len(c.Set.Symbols))
			for _, s := range c.Set.String {
				set[biscuit.String(s)] = struct{}{}
			}
			constraint.Checker = biscuit.StringInChecker{
				Set: set,
				Not: c.Set.Not,
			}
		default:
			return nil, errors.New("parser: unsupported set type, must be one of symbols, int or string")
		}
	default:
		return nil, errors.New("parser: unsupported variable constraint, must be one of date, int, string or set")
	}
	return constraint, nil
}

func convertFunctionConstraint(c *FunctionConstraint) (*biscuit.Constraint, error) {
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

func convertRule(r *Rule) (*biscuit.Rule, error) {
	body := make([]biscuit.Predicate, len(r.Body))
	for i, p := range r.Body {
		b, err := convertPredicate(p)
		if err != nil {
			return nil, err
		}
		body[i] = *b
	}

	constraints := make([]biscuit.Constraint, len(r.Constraints))
	for i, c := range r.Constraints {
		constraint, err := convertConstraint(c)
		if err != nil {
			return nil, err
		}
		constraints[i] = *constraint
	}

	head, err := convertPredicate(r.Head)
	if err != nil {
		return nil, err
	}

	return &biscuit.Rule{
		Head:        *head,
		Body:        body,
		Constraints: constraints,
	}, nil
}

func convertQuery(q *Query) (*biscuit.Rule, error) {
	body := make([]biscuit.Predicate, len(q.Body))
	for i, p := range q.Body {
		b, err := convertPredicate(p)
		if err != nil {
			return nil, err
		}
		body[i] = *b
	}

	constraints := make([]biscuit.Constraint, len(q.Constraints))
	for i, c := range q.Constraints {
		constraint, err := convertConstraint(c)
		if err != nil {
			return nil, err
		}
		constraints[i] = *constraint
	}

	return &biscuit.Rule{
		Body:        body,
		Constraints: constraints,
	}, nil
}
