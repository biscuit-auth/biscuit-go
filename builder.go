package biscuit

import (
	"errors"
	"io"

	"github.com/flynn/biscuit-go/datalog"
	"github.com/flynn/biscuit-go/sig"
)

var (
	ErrDuplicateFact = errors.New("biscuit: fact already exists")
)

type Builder interface {
	AddAuthorityFact(fact *Fact) error
	AddAuthorityRule(rule *Rule) error
	AddAuthorityCaveat(rule *Rule) error
	AddRight(resource, right string) error
	Build() (*Biscuit, error)
}

type builder struct {
	rng  io.Reader
	root sig.Keypair

	symbolsStart int
	symbols      *datalog.SymbolTable
	facts        *datalog.FactSet
	rules        []*datalog.Rule
	caveats      []*datalog.Caveat
	context      string
}

func NewBuilder(rng io.Reader, root sig.Keypair) Builder {
	return BuilderWithSymbols(rng, root, DefaultSymbolTable)
}

func BuilderWithSymbols(rng io.Reader, root sig.Keypair, symbols *datalog.SymbolTable) Builder {
	return &builder{
		rng:  rng,
		root: root,

		symbolsStart: symbols.Len(),
		symbols:      symbols,
		facts:        new(datalog.FactSet),
	}
}

func (b *builder) AddAuthorityFact(fact *Fact) error {
	if len(fact.Predicate.IDs) == 0 || fact.Predicate.IDs[0] != SymAuthority {
		fact.Predicate.IDs[0] = SymAuthority
	}

	dlFact := fact.convert(b.symbols)
	if !b.facts.Insert(dlFact) {
		return ErrDuplicateFact
	}

	return nil
}

func (b *builder) AddAuthorityRule(rule *Rule) error {
	if len(rule.Head.IDs) == 0 || rule.Head.IDs[0] != SymAuthority {
		rule.Head.IDs[0] = SymAuthority
	}

	dlRule := rule.convert(b.symbols)
	b.rules = append(b.rules, &dlRule)
	return nil
}

func (b *builder) AddAuthorityCaveat(rule *Rule) error {
	b.caveats = append(b.caveats, &datalog.Caveat{Queries: []datalog.Rule{rule.convert(b.symbols)}})
	return nil
}

func (b *builder) AddRight(resource, right string) error {
	return b.AddAuthorityFact(&Fact{
		Predicate: Predicate{
			Name: "right",
			IDs: []Atom{
				SymAuthority,
				String(resource),
				Symbol(right),
			},
		},
	})
}

func (b *builder) Build() (*Biscuit, error) {
	return New(b.rng, b.root, b.symbols, &Block{
		index:   0,
		symbols: b.symbols.SplitOff(b.symbolsStart),
		facts:   b.facts,
		rules:   b.rules,
		caveats: b.caveats,
		context: b.context,
	})
}
