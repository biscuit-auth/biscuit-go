// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	stdcrypto "crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/internal/crypto"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"

	//"github.com/eclipse-biscuit/biscuit-go/sig"
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
	// AddAuthorityScope sets the default scope of the authority block's
	// rules and checks; see Scope.
	AddAuthorityScope(scope Scope)
	SetContext(string)
	Build() (*Biscuit, error)
}

type builderOptions struct {
	rng       io.Reader
	rootKey   crypto.Signer
	rootKeyID *uint32

	symbolsStart int
	symbols      *datalog.SymbolTable
	facts        *datalog.FactSet
	rules        []datalog.Rule
	checks       []datalog.Check
	scopes       []datalog.Scope
	context      string
}

type builderOption interface {
	applyToBuilder(b *builderOptions)
}

type symbolsOption struct {
	*datalog.SymbolTable
}

func (o symbolsOption) applyToBuilder(b *builderOptions) {
	b.symbolsStart = o.Len()
	b.symbols = o.Clone()
}

// WithSymbols supplies a symbol table to use when composing biscuits.
func WithSymbols(symbols *datalog.SymbolTable) builderOption {
	return symbolsOption{symbols}
}

// NewBuilder creates a Builder signing the authority block with an Ed25519
// root key. Use NewBuilderWithSigner for other algorithms.
func NewBuilder(root ed25519.PrivateKey, opts ...builderOption) Builder {
	return NewBuilderWithSigner(root, opts...)
}

// NewBuilderWithSigner creates a Builder signing the authority block with the
// given root key: an ed25519.PrivateKey or an *ecdsa.PrivateKey on the P-256
// curve. Any other key makes Build return ErrUnsupportedAlgorithm.
func NewBuilderWithSigner(root stdcrypto.Signer, opts ...builderOption) Builder {
	signer, err := crypto.NewSigner(root)
	if err != nil {
		signer = nil
	}
	return newBuilder(signer, opts...)
}

func newBuilder(root crypto.Signer, opts ...builderOption) Builder {
	b := &builderOptions{
		rootKey:      root,
		symbols:      defaultSymbolTable.Clone(),
		symbolsStart: defaultSymbolTable.Len(),
		facts:        new(datalog.FactSet),
	}

	for _, o := range opts {
		o.applyToBuilder(b)
	}

	return b
}

func (b *builderOptions) AddBlock(block ParsedBlock) error {
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

func (b *builderOptions) AddAuthorityFact(fact Fact) error {
	dlFact := fact.convert(b.symbols)
	if !b.facts.Insert(dlFact) {
		return ErrDuplicateFact
	}

	return nil
}

func (b *builderOptions) AddAuthorityRule(rule Rule) error {
	dlRule := rule.convert(b.symbols)
	b.rules = append(b.rules, dlRule)
	return nil
}

func (b *builderOptions) AddAuthorityCheck(check Check) error {
	b.checks = append(b.checks, check.convert(b.symbols))
	return nil
}

func (b *builderOptions) AddAuthorityScope(scope Scope) {
	b.scopes = append(b.scopes, scope)
}

func (b *builderOptions) SetContext(context string) {
	b.context = context
}

func (b *builderOptions) Build() (*Biscuit, error) {
	if b.rootKey == nil {
		return nil, ErrUnsupportedAlgorithm
	}
	opts := make([]biscuitOption, 0, 2)
	if v := b.rng; v != nil {
		opts = append(opts, WithRNG(b.rng))
	}
	if v := b.rootKeyID; v != nil {
		opts = append(opts, WithRootKeyID(*v))
	}
	return newBiscuit(
		b.rootKey,
		b.symbols,
		&Block{
			symbols:    b.symbols.SplitOff(b.symbolsStart),
			facts:      b.facts,
			rules:      b.rules,
			checks:     b.checks,
			scopes:     b.scopes,
			publicKeys: scopeKeys(b.scopes, b.rules, b.checks),
			context:    b.context,
			version:    schemaVersion(b.scopes, b.rules, b.checks),
		},
		opts...)
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

	if err := checkSignedBlockFormat(container.Authority); err != nil {
		return nil, err
	}

	pbAuthority := new(pb.Block)
	if err := proto.Unmarshal(container.Authority.Block, pbAuthority); err != nil {
		return nil, err
	}

	var publicKeys publicKeyTable
	authority, err := protoBlockToTokenBlock(pbAuthority, publicKeys)
	if err != nil {
		return nil, err
	}

	symbols.Extend(authority.symbols)
	publicKeys = publicKeys.with(authority.publicKeys...)

	blocks := make([]*Block, len(container.Blocks))
	for i, sb := range container.Blocks {
		if err := checkSignedBlockFormat(sb); err != nil {
			return nil, err
		}

		pbBlock := new(pb.Block)
		if err := proto.Unmarshal(sb.Block, pbBlock); err != nil {
			return nil, err
		}

		if sb.ExternalSignature == nil {
			block, err := protoBlockToTokenBlock(pbBlock, publicKeys)
			if err != nil {
				return nil, err
			}
			blocks[i] = block
			publicKeys = publicKeys.with(block.publicKeys...)
			symbols.Extend(block.symbols)
			continue
		}

		// A third-party block has its own tables and leaves the token's alone.
		block, err := thirdPartyBlock(pbBlock, sb.ExternalSignature)
		if err != nil {
			return nil, err
		}
		blocks[i] = block
	}

	return &Biscuit{
		authority:  authority,
		symbols:    symbols,
		publicKeys: publicKeys,
		blocks:     blocks,
		container:  container,
	}, nil
}

type BlockBuilder interface {
	AddBlock(block ParsedBlock) error
	AddFact(fact Fact) error
	AddRule(rule Rule) error
	AddCheck(check Check) error
	// AddScope sets the default scope of the block's rules and checks; see
	// Scope.
	AddScope(scope Scope)
	SetContext(string)
	Build() *Block
}

type blockBuilder struct {
	symbolsStart int
	symbols      *datalog.SymbolTable
	// publicKeys is the key table of the token the block is appended to.
	publicKeys publicKeyTable
	facts      *datalog.FactSet
	rules      []datalog.Rule
	checks     []datalog.Check
	scopes     []datalog.Scope
	context    string
}

var _ BlockBuilder = (*blockBuilder)(nil)

func NewBlockBuilder(baseSymbols *datalog.SymbolTable) BlockBuilder {
	return newBlockBuilder(baseSymbols, nil)
}

func newBlockBuilder(baseSymbols *datalog.SymbolTable, publicKeys publicKeyTable) BlockBuilder {
	return &blockBuilder{
		symbolsStart: baseSymbols.Len(),
		symbols:      baseSymbols,
		publicKeys:   publicKeys,
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
	for _, s := range block.Scopes {
		b.AddScope(s)
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

func (b *blockBuilder) AddScope(scope Scope) {
	b.scopes = append(b.scopes, scope)
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

	// Only the keys the token does not have yet are carried by the block.
	var publicKeys []datalog.PublicKey
	for _, k := range scopeKeys(b.scopes, rules, checks) {
		if _, known := b.publicKeys.index(k); !known {
			publicKeys = append(publicKeys, k)
		}
	}

	return &Block{
		symbols:    b.symbols.Clone(),
		facts:      &facts,
		rules:      rules,
		checks:     checks,
		scopes:     slices.Clone(b.scopes),
		publicKeys: publicKeys,
		context:    b.context,
		version:    schemaVersion(b.scopes, rules, checks),
	}
}

// checkSignedBlockFormat rejects a block whose next key or signature cannot be
// the encoding of its algorithm, before any verification. Ed25519 has fixed
// sizes; ECDSA signatures are DER and only the key is checked.
func checkSignedBlockFormat(sb *pb.SignedBlock) error {
	if _, err := crypto.ParseVerifier(sb.GetNextKey().GetAlgorithm(), sb.GetNextKey().GetKey()); err != nil {
		return err
	}
	if sb.GetNextKey().GetAlgorithm() == pb.PublicKey_Ed25519 && len(sb.GetSignature()) != ed25519.SignatureSize {
		return ErrInvalidSignatureSize
	}
	return nil
}

// thirdPartyBlock converts a block signed by a third party: its scopes refer
// to its own key table, and its version must be at least datalog v3.2.
func thirdPartyBlock(pbBlock *pb.Block, ext *pb.ExternalSignature) (*Block, error) {
	if pbBlock.GetVersion() < blockVersion3_2 {
		return nil, fmt.Errorf("biscuit: failed to convert proto block to token block: third-party blocks require block version %d, got %d", blockVersion3_2, pbBlock.GetVersion())
	}
	block, err := protoBlockToTokenBlock(pbBlock, nil)
	if err != nil {
		return nil, err
	}
	externalKey, err := protoPublicKeyToTokenPublicKey(ext.GetPublicKey())
	if err != nil {
		return nil, err
	}
	block.externalKey = &externalKey
	return block, nil
}
