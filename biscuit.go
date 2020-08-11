package biscuit

import (
	"crypto/rand"
	"errors"
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
	ErrSymbolTableOverlap = errors.New("symbol table overlap")
	// ErrInvalidAuthorityIndex occurs when an authority block index is not 0
	ErrInvalidAuthorityIndex = errors.New("invalid authority index")
)

func New(rng io.Reader, root sig.Keypair, symbols *datalog.SymbolTable, authority *Block) (*Biscuit, error) {
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
	ts.Sign(rand.Reader, root, pbAuthority)

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

func (b *Biscuit) Serialize() ([]byte, error) {
	return proto.Marshal(b.container)
}
