package parser

import (
	"errors"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"github.com/biscuit-auth/biscuit-go/v2"
)

var (
	ErrVariableInFact = errors.New("parser: a fact cannot contain any variables")
	ErrVariableInSet  = errors.New("parser: a set cannot contain any variables")
)

var BiscuitLexerRules = []lexer.Rule{
	{Name: "Keyword", Pattern: `check if|allow if|deny if`},
	{Name: "Function", Pattern: `prefix|suffix|matches|length|contains`},
	{Name: "Hex", Pattern: `hex:`},
	{Name: "Dot", Pattern: `\.`},
	{Name: "Arrow", Pattern: `<-`},
	{Name: "Or", Pattern: `\|\|`},
	{Name: "Operator", Pattern: `==|>=|<=|>|<|not|in`},
	{Name: "Comment", Pattern: `//[^\n]*`},
	{Name: "String", Pattern: `\"[^\"]*\"`},
	{Name: "Variable", Pattern: `\$[a-zA-Z0-9_]+`},
	{Name: "DateTime", Pattern: `\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|([-+]\d\d:\d\d))?`},
	{Name: "Int", Pattern: `[0-9]+`},
	{Name: "Bool", Pattern: `true|false`},
	{Name: "Ident", Pattern: `[a-zA-Z0-9_:]+`},
	{Name: "Whitespace", Pattern: `[ \t]+`},
	{Name: "EOL", Pattern: `[\n\r]+`},
	{Name: "Punct", Pattern: `[-[!@%^&#$*()+_={}\|:;"'<,>.?/]|]`},
}

var DefaultParserOptions = []participle.Option{
	participle.Lexer(lexer.MustSimple(BiscuitLexerRules)),
	participle.UseLookahead(1),
	participle.Elide("Whitespace", "EOL"),
	participle.Unquote("String"),
}

type Parser interface {
	Fact(fact string) (biscuit.Fact, error)
	Rule(rule string) (biscuit.Rule, error)
	Check(check string) (biscuit.Check, error)
	Policy(policy string) (biscuit.Policy, error)

	Must() MustParser
}

type MustParser interface {
	Fact(fact string) biscuit.Fact
	Rule(rule string) biscuit.Rule
	Check(check string) biscuit.Check
	Policy(policy string) biscuit.Policy
}

type parser struct {
	factParser   *participle.Parser
	ruleParser   *participle.Parser
	checkParser  *participle.Parser
	policyParser *participle.Parser
}

var _ Parser = (*parser)(nil)

type mustParser struct {
	parser Parser
}

var _ MustParser = (*mustParser)(nil)

func New() Parser {
	return &parser{
		factParser:   participle.MustBuild(&Predicate{}, DefaultParserOptions...),
		ruleParser:   participle.MustBuild(&Rule{}, DefaultParserOptions...),
		checkParser:  participle.MustBuild(&Check{}, DefaultParserOptions...),
		policyParser: participle.MustBuild(&Policy{}, DefaultParserOptions...),
	}
}

func (p *parser) Fact(fact string) (biscuit.Fact, error) {
	parsed := &Predicate{}
	if err := p.factParser.ParseString("fact", fact, parsed); err != nil {
		return biscuit.Fact{}, err
	}

	pred, err := parsed.ToBiscuit()
	if err != nil {
		return biscuit.Fact{}, err
	}

	for _, a := range pred.IDs {
		if a.Type() == biscuit.TermTypeVariable {
			return biscuit.Fact{}, ErrVariableInFact
		}
	}

	return biscuit.Fact{Predicate: *pred}, nil
}

func (p *parser) Rule(rule string) (biscuit.Rule, error) {
	parsed := &Rule{}
	if err := p.ruleParser.ParseString("rule", rule, parsed); err != nil {
		return biscuit.Rule{}, err
	}

	r, err := parsed.ToBiscuit()
	if err != nil {
		return biscuit.Rule{}, err
	}

	return *r, nil
}

func (p *parser) Check(check string) (biscuit.Check, error) {
	parsed := &Check{}
	if err := p.checkParser.ParseString("check", check, parsed); err != nil {
		return biscuit.Check{}, err
	}

	queries := make([]biscuit.Rule, len(parsed.Queries))
	for i, q := range parsed.Queries {
		query, err := q.ToBiscuit()
		if err != nil {
			return biscuit.Check{}, err
		}

		queries[i] = *query
	}

	return biscuit.Check{
		Queries: queries,
	}, nil
}

func (p *parser) Policy(policy string) (biscuit.Policy, error) {
	parsed := &Policy{}
	if err := p.policyParser.ParseString("policy", policy, parsed); err != nil {
		return biscuit.Policy{}, err
	}

	var parsedQueries []*CheckQuery
	var kind biscuit.PolicyKind
	switch {
	case parsed.Allow != nil:
		{
			parsedQueries = parsed.Allow.Queries
			kind = biscuit.PolicyKindAllow
			break
		}
	case parsed.Deny != nil:
		{
			parsedQueries = parsed.Deny.Queries
			kind = biscuit.PolicyKindDeny
			break
		}
	}

	queries := make([]biscuit.Rule, len(parsedQueries))
	for i, q := range parsedQueries {
		query, err := q.ToBiscuit()
		if err != nil {
			return biscuit.Policy{}, err
		}

		queries[i] = *query
	}

	return biscuit.Policy{
		Kind:    kind,
		Queries: queries,
	}, nil
}

func (p *parser) Must() MustParser {
	return &mustParser{parser: p}
}

func (m *mustParser) Fact(fact string) biscuit.Fact {
	f, err := m.parser.Fact(fact)
	if err != nil {
		panic(err)
	}

	return f
}

func (m *mustParser) Rule(rule string) biscuit.Rule {
	r, err := m.parser.Rule(rule)
	if err != nil {
		panic(err)
	}

	return r
}

func (m *mustParser) Check(check string) biscuit.Check {
	c, err := m.parser.Check(check)
	if err != nil {
		panic(err)
	}

	return c
}

func (m *mustParser) Policy(policy string) biscuit.Policy {
	c, err := m.parser.Policy(policy)
	if err != nil {
		panic(err)
	}

	return c
}

func FromStringFact(input string) (biscuit.Fact, error) {
	p := New()

	return p.Fact(input)
}

func FromStringRule(input string) (biscuit.Rule, error) {
	p := New()

	return p.Rule(input)
}

func FromStringCheck(input string) (biscuit.Check, error) {
	p := New()

	return p.Check(input)
}

func FromStringPolicy(input string) (biscuit.Policy, error) {
	p := New()

	return p.Policy(input)
}
