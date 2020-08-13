package biscuit

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/flynn/biscuit-go/datalog"
	"github.com/flynn/biscuit-go/pb"
	"github.com/flynn/biscuit-go/sig"
	"google.golang.org/protobuf/proto"
)

// Biscuit represents a valid Biscuit token
// It contains multiple `Block` elements, the associated symbol table,
// and a serialized version of this data
type Biscuit struct {
	authority *Block
	blocks    []*Block
	symbols   *datalog.SymbolTable
	container *pb.Biscuit
}

var (
	// ErrSymbolTableOverlap is returned when multiple blocks declare the same symbols
	ErrSymbolTableOverlap = errors.New("biscuit: symbol table overlap")
	// ErrInvalidAuthorityIndex occurs when an authority block index is not 0
	ErrInvalidAuthorityIndex = errors.New("biscuit: invalid authority index")
)

func New(rng io.Reader, root sig.Keypair, symbols *datalog.SymbolTable, authority *Block) (*Biscuit, error) {
	if rng == nil {
		rng = rand.Reader
	}

	if !symbols.IsDisjoint(authority.symbols) {
		return nil, ErrSymbolTableOverlap
	}

	if authority.index != 0 {
		return nil, ErrInvalidAuthorityIndex
	}

	symbols.Extend(authority.symbols)

	pbAuthority, err := proto.Marshal(tokenBlockToProtoBlock(authority))
	if err != nil {
		return nil, err
	}

	ts := &sig.TokenSignature{}
	ts.Sign(rng, root, pbAuthority)

	container := &pb.Biscuit{
		Authority: pbAuthority,
		Blocks:    [][]byte{},
		Keys:      [][]byte{root.Public().Bytes()},
		Signature: tokenSignatureToProtoSignature(ts),
	}

	return &Biscuit{
		authority: authority,
		blocks:    []*Block{},
		symbols:   symbols,
		container: container,
	}, nil
}

func (b *Biscuit) CreateBlock() BlockBuilder {
	return NewBlockBuilder(uint32(len(b.blocks)+1), b.symbols.Clone())
}

func (b *Biscuit) Append(rng io.Reader, keypair sig.Keypair, block *Block) (*Biscuit, error) {
	if b.container == nil {
		return nil, errors.New("biscuit: append failed, token is sealed")
	}

	if !b.symbols.IsDisjoint(block.symbols) {
		return nil, ErrSymbolTableOverlap
	}

	if int(block.index) != len(b.blocks)+1 {
		return nil, ErrInvalidBlockIndex
	}

	// clone biscuit fields and append new block
	authority := new(Block)
	*authority = *b.authority

	blocks := make([]*Block, len(b.blocks)+1)
	for i, oldBlock := range b.blocks {
		blocks[i] = new(Block)
		*blocks[i] = *oldBlock
	}
	blocks[len(b.blocks)] = block

	symbols := b.symbols.Clone()
	symbols.Extend(block.symbols)

	// serialize and sign the new block
	pbBlock, err := proto.Marshal(tokenBlockToProtoBlock(block))
	if err != nil {
		return nil, err
	}

	ts := &sig.TokenSignature{}
	ts.Sign(rng, keypair, pbBlock)

	// clone container and append new marshalled block and public key
	container := &pb.Biscuit{
		Authority: append([]byte{}, b.container.Authority...),
		Blocks:    append([][]byte{}, b.container.Blocks...),
		Keys:      append([][]byte{}, b.container.Keys...),
		Signature: tokenSignatureToProtoSignature(ts),
	}

	container.Blocks = append(container.Blocks, pbBlock)
	container.Keys = append(container.Keys, keypair.Public().Bytes())

	return &Biscuit{
		authority: authority,
		blocks:    blocks,
		symbols:   symbols,
		container: container,
	}, nil

}

func (b *Biscuit) Serialize() ([]byte, error) {
	return proto.Marshal(b.container)
}

func (b *Biscuit) Print() string {
	blocks := make([]string, len(b.blocks))
	for i, block := range b.blocks {
		blocks[i] = block.Print(b.symbols)
	}

	return fmt.Sprintf(`
Biscuit {
	symbols: %+q
	authority: %s
	blocks: %v
}`,
		*b.symbols,
		b.authority.Print(b.symbols),
		blocks,
	)
}
