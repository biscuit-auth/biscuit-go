package biscuit

import (
	"errors"
	"io"

	"github.com/flynn/biscuit-go/datalog"
	"github.com/flynn/biscuit-go/pb"
	"github.com/flynn/biscuit-go/sig"
	"google.golang.org/protobuf/proto"
)

var (
	ErrDuplicateFact     = errors.New("biscuit: fact already exists")
	ErrInvalidBlockIndex = errors.New("biscuit: invalid block index")
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

func From(serialized []byte) (*Biscuit, error) {
	return FromWithSymbols(serialized, DefaultSymbolTable)
}

func FromWithSymbols(serialized []byte, symbols *datalog.SymbolTable) (*Biscuit, error) {
	container := new(pb.Biscuit)
	if err := proto.Unmarshal(serialized, container); err != nil {
		return nil, err
	}

	pbAuthority := new(pb.Block)
	if err := proto.Unmarshal(container.Authority, pbAuthority); err != nil {
		return nil, err
	}

	signature, err := protoSignatureToTokenSignature(container.Signature)
	if err != nil {
		return nil, err
	}

	pubKeys := make([]sig.PublicKey, len(container.Keys))
	for i, pk := range container.Keys {
		pubKey, err := sig.NewPublicKey(pk)
		if err != nil {
			return nil, err
		}
		pubKeys[i] = pubKey
	}

	signedBlocks := [][]byte{container.Authority}
	signedBlocks = append(signedBlocks, container.Blocks...)
	if err := signature.Verify(pubKeys, signedBlocks); err != nil {
		return nil, err
	}

	authority := protoBlockToTokenBlock(pbAuthority)
	if authority.index != 0 {
		return nil, ErrInvalidAuthorityIndex
	}
	symbols.Extend(authority.symbols)

	blocks := make([]*Block, len(container.Blocks))
	for i, sb := range container.Blocks {
		pbBlock := new(pb.Block)
		if err := proto.Unmarshal(sb, pbBlock); err != nil {
			return nil, err
		}

		if int(pbBlock.Index) != i+1 {
			return nil, ErrInvalidBlockIndex
		}

		blocks[i] = protoBlockToTokenBlock(pbBlock)
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
	AddFact(fact Fact) error
	AddRule(rule Rule) error
	AddCaveat(caveat Caveat) error
	SetContext(string)
	Build() *Block
}

type blockBuilder struct {
	index        uint32
	symbolsStart int
	symbols      *datalog.SymbolTable
	facts        *datalog.FactSet
	rules        []*datalog.Rule
	caveats      []*datalog.Caveat
	context      string
}

var _ BlockBuilder = (*blockBuilder)(nil)

func NewBlockBuilder(index uint32, baseSymbols *datalog.SymbolTable) BlockBuilder {
	return &blockBuilder{
		index:        index,
		symbolsStart: baseSymbols.Len(),
		symbols:      baseSymbols,
		facts:        new(datalog.FactSet),
	}
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
	b.rules = append(b.rules, &dlRule)

	return nil
}

func (b *blockBuilder) AddCaveat(caveat Caveat) error {
	dlCaveat := caveat.convert(b.symbols)
	b.caveats = append(b.caveats, &dlCaveat)

	return nil
}

func (b *blockBuilder) SetContext(context string) {
	b.context = context
}

func (b *blockBuilder) Build() *Block {
	b.symbols = b.symbols.SplitOff(b.symbolsStart)
	return &Block{
		index:   b.index,
		symbols: b.symbols,
		facts:   b.facts,
		rules:   b.rules,
		caveats: b.caveats,
		context: b.context,
	}
}
