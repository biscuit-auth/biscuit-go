package biscuit

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"

	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/biscuit-auth/biscuit-go/v2/pb"

	//"github.com/biscuit-auth/biscuit-go/sig"
	"google.golang.org/protobuf/proto"
)

var (
	ErrDuplicateFact     = errors.New("biscuit: fact already exists")
	ErrInvalidBlockIndex = errors.New("biscuit: invalid block index")
)

type Builder interface {
	AddBlock(block ParsedBlock) error
	AddAuthorityFact(fact Fact) error
	AddAuthorityRule(rule Rule) error
	AddAuthorityCheck(check Check) error
	Build() (*Biscuit, error)
}

type builder struct {
	rng  io.Reader
	root ed25519.PrivateKey

	symbolsStart int
	symbols      *datalog.SymbolTable
	facts        *datalog.FactSet
	rules        []datalog.Rule
	checks       []datalog.Check
	context      string
}

type builderOption func(b *builder)

func WithRandom(rng io.Reader) builderOption {
	return func(b *builder) {
		b.rng = rng
	}
}

func WithSymbols(symbols *datalog.SymbolTable) builderOption {
	return func(b *builder) {
		b.symbolsStart = symbols.Len()
		b.symbols = symbols.Clone()
	}
}

func NewBuilder(root ed25519.PrivateKey, opts ...builderOption) Builder {
	b := &builder{
		rng:          rand.Reader,
		root:         root,
		symbols:      defaultSymbolTable.Clone(),
		symbolsStart: defaultSymbolTable.Len(),
		facts:        new(datalog.FactSet),
	}

	for _, o := range opts {
		o(b)
	}

	return b
}

func (b *builder) AddBlock(block ParsedBlock) error {
	for _, f := range block.Facts {
		if err := b.AddAuthorityFact(f); err != nil {
			return err
		}
	}
	for _, r := range block.Rules {
		err := b.AddAuthorityRule(r)
		if err != nil {
			return err
		}
	}
	for _, c := range block.Checks {
		err := b.AddAuthorityCheck(c)
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *builder) AddAuthorityFact(fact Fact) error {
	dlFact := fact.convert(b.symbols)
	if !b.facts.Insert(dlFact) {
		return ErrDuplicateFact
	}

	return nil
}

func (b *builder) AddAuthorityRule(rule Rule) error {
	dlRule := rule.convert(b.symbols)
	b.rules = append(b.rules, dlRule)
	return nil
}

func (b *builder) AddAuthorityCheck(check Check) error {
	b.checks = append(b.checks, check.convert(b.symbols))
	return nil
}

func (b *builder) Build() (*Biscuit, error) {
	return New(b.rng, b.root, b.symbols, &Block{
		symbols: b.symbols.SplitOff(b.symbolsStart),
		facts:   b.facts,
		rules:   b.rules,
		checks:  b.checks,
		context: b.context,
		version: MaxSchemaVersion,
	})
}

type Unmarshaler struct {
	Symbols *datalog.SymbolTable
}

func Unmarshal(serialized []byte) (*Biscuit, error) {
	return (&Unmarshaler{Symbols: defaultSymbolTable.Clone()}).Unmarshal(serialized)
}

func (u *Unmarshaler) Unmarshal(serialized []byte) (*Biscuit, error) {
	if u.Symbols == nil {
		return nil, errors.New("biscuit: unmarshaler requires a symbol table")
	}

	symbols := u.Symbols.Clone()

	container := new(pb.Biscuit)
	if err := proto.Unmarshal(serialized, container); err != nil {
		return nil, err
	}

	if len(container.Authority.NextKey.Key) != 32 {
		return nil, ErrInvalidKeySize
	}
	if len(container.Authority.Signature) != 64 {
		return nil, ErrInvalidSignatureSize
	}

	pbAuthority := new(pb.Block)
	if err := proto.Unmarshal(container.Authority.Block, pbAuthority); err != nil {
		return nil, err
	}

	authority, err := protoBlockToTokenBlock(pbAuthority)
	if err != nil {
		return nil, err
	}

	symbols.Extend(authority.symbols)

	blocks := make([]*Block, len(container.Blocks))
	for i, sb := range container.Blocks {
		if len(sb.NextKey.Key) != 32 {
			return nil, ErrInvalidKeySize
		}
		if len(sb.Signature) != 64 {
			return nil, ErrInvalidSignatureSize
		}

		pbBlock := new(pb.Block)
		if err := proto.Unmarshal(sb.Block, pbBlock); err != nil {
			return nil, err
		}

		block, err := protoBlockToTokenBlock(pbBlock)
		if err != nil {
			return nil, err
		}
		blocks[i] = block
		symbols.Extend(blocks[i].symbols)
	}

	return &Biscuit{
		authority: authority,
		symbols:   symbols,
		blocks:    blocks,
		container: container,
	}, nil
}

type BlockBuilder interface {
	AddBlock(block ParsedBlock) error
	AddFact(fact Fact) error
	AddRule(rule Rule) error
	AddCheck(check Check) error
	SetContext(string)
	Build() *Block
}

type blockBuilder struct {
	symbolsStart int
	symbols      *datalog.SymbolTable
	facts        *datalog.FactSet
	rules        []datalog.Rule
	checks       []datalog.Check
	context      string
}

var _ BlockBuilder = (*blockBuilder)(nil)

func NewBlockBuilder(baseSymbols *datalog.SymbolTable) BlockBuilder {
	return &blockBuilder{
		symbolsStart: baseSymbols.Len(),
		symbols:      baseSymbols,
		facts:        new(datalog.FactSet),
	}
}

func (b *blockBuilder) AddBlock(block ParsedBlock) error {
	for _, f := range block.Facts {
		err := b.AddFact(f)
		if err != nil {
			return err
		}
	}
	for _, r := range block.Rules {
		err := b.AddRule(r)
		if err != nil {
			return err
		}
	}
	for _, c := range block.Checks {
		err := b.AddCheck(c)
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *blockBuilder) AddFact(fact Fact) error {
	dlFact := fact.convert(b.symbols)
	if !b.facts.Insert(dlFact) {
		return ErrDuplicateFact
	}

	return nil
}

func (b *blockBuilder) AddRule(rule Rule) error {
	dlRule := rule.convert(b.symbols)
	b.rules = append(b.rules, dlRule)

	return nil
}

func (b *blockBuilder) AddCheck(check Check) error {
	dlCheck := check.convert(b.symbols)
	b.checks = append(b.checks, dlCheck)

	return nil
}

func (b *blockBuilder) SetContext(context string) {
	b.context = context
}

func (b *blockBuilder) Build() *Block {
	b.symbols = b.symbols.SplitOff(b.symbolsStart)

	facts := make(datalog.FactSet, len(*b.facts))
	copy(facts, *b.facts)

	rules := make([]datalog.Rule, len(b.rules))
	copy(rules, b.rules)

	checks := make([]datalog.Check, len(b.checks))
	copy(checks, b.checks)

	return &Block{
		symbols: b.symbols.Clone(),
		facts:   &facts,
		rules:   rules,
		checks:  checks,
		context: b.context,
		version: MaxSchemaVersion,
	}
}
