package parser

import (
	"errors"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer/stateful"
	"github.com/flynn/biscuit-go"
)

var (
	ErrVariableInFact = errors.New("parser: a fact cannot contain any variables")
	ErrVariableInSet  = errors.New("parser: a set cannot contain any variables")
)

var biscuitLexerRules = []stateful.Rule{
	{Name: "Keyword", Pattern: `rules|caveats`, Action: nil},
	{Name: "Function", Pattern: `prefix|suffix|match`, Action: nil},
	{Name: "Arrow", Pattern: `<-`, Action: nil},
	{Name: "Or", Pattern: `\|\|`, Action: nil},
	{Name: "Operator", Pattern: `==|>=|<=|>|<|not|in`, Action: nil},
	{Name: "Comment", Pattern: `//[^\n]*`, Action: nil},
	{Name: "String", Pattern: `\"[^\"]*\"`, Action: nil},
	{Name: "Variable", Pattern: `\$[a-zA-Z0-9_]+`, Action: nil},
	{Name: "Int", Pattern: `[0-9]+`, Action: nil},
	{Name: "Symbol", Pattern: `#[a-zA-Z0-9_]+`, Action: nil},
	{Name: "Ident", Pattern: `[a-zA-Z0-9_]+`, Action: nil},
	{Name: "Whitespace", Pattern: `[ \t]+`, Action: nil},
	{Name: "EOL", Pattern: `[\n\r]+`, Action: nil},
	{Name: "Punct", Pattern: `[-[!@%^&#$*()+_={}\|:;"'<,>.?/]|]`, Action: nil},
}

var defaultParserOptions = []participle.Option{
	participle.Lexer(stateful.MustSimple(biscuitLexerRules)),
	participle.UseLookahead(1),
	participle.Elide("Whitespace", "EOL"),
	participle.Unquote("String"),
}

type Parser interface {
	Fact(fact string) (biscuit.Fact, error)
	Rule(rule string) (biscuit.Rule, error)
	Caveat(caveat string) (biscuit.Caveat, error)
	Must() MustParser
}

type MustParser interface {
	Fact(fact string) biscuit.Fact
	Rule(rule string) biscuit.Rule
	Caveat(caveat string) biscuit.Caveat
}

type parser struct {
	factParser   *participle.Parser
	ruleParser   *participle.Parser
	caveatParser *participle.Parser
}

var _ Parser = (*parser)(nil)

type mustParser struct {
	parser Parser
}

var _ MustParser = (*mustParser)(nil)

func New() Parser {
	return &parser{
		factParser:   participle.MustBuild(&Predicate{}, defaultParserOptions...),
		ruleParser:   participle.MustBuild(&Rule{}, defaultParserOptions...),
		caveatParser: participle.MustBuild(&Caveat{}, defaultParserOptions...),
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
		if a.Type() == biscuit.AtomTypeVariable {
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

func (p *parser) Caveat(caveat string) (biscuit.Caveat, error) {
	parsed := &Caveat{}
	if err := p.caveatParser.ParseString("caveat", caveat, parsed); err != nil {
		return biscuit.Caveat{}, err
	}

	queries := make([]biscuit.Rule, len(parsed.Queries))
	for i, q := range parsed.Queries {
		query, err := q.ToBiscuit()
		if err != nil {
			return biscuit.Caveat{}, err
		}

		queries[i] = *query
	}

	return biscuit.Caveat{
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

func (m *mustParser) Caveat(caveat string) biscuit.Caveat {
	c, err := m.parser.Caveat(caveat)
	if err != nil {
		panic(err)
	}

	return c
}
