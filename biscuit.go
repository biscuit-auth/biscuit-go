// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/internal/crypto"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
	"google.golang.org/protobuf/proto"
)

// Biscuit represents a valid Biscuit token
// It contains multiple `Block` elements, the associated symbol table,
// and a serialized version of this data
type Biscuit struct {
	authority *Block
	blocks    []*Block
	symbols   *datalog.SymbolTable
	// publicKeys is the key table of the token: the keys the scopes of its
	// blocks refer to, in order of introduction.
	publicKeys publicKeyTable
	container  *pb.Biscuit
}

var (
	// ErrSymbolTableOverlap is returned when multiple blocks declare the same symbols
	ErrSymbolTableOverlap = errors.New("biscuit: symbol table overlap")
	// ErrInvalidAuthorityIndex occurs when an authority block index is not 0
	ErrInvalidAuthorityIndex = errors.New("biscuit: invalid authority index")
	// ErrInvalidAuthorityFact occurs when an authority fact is an ambient fact
	ErrInvalidAuthorityFact = errors.New("biscuit: invalid authority fact")
	// ErrInvalidBlockFact occurs when a block fact provides an authority or ambient fact
	ErrInvalidBlockFact = errors.New("biscuit: invalid block fact")
	// ErrInvalidBlockRule occurs when a block rule generate an authority or ambient fact
	ErrInvalidBlockRule = errors.New("biscuit: invalid block rule")
	// ErrEmptyKeys is returned when verifying a biscuit having no keys
	ErrEmptyKeys = errors.New("biscuit: empty keys")
	// ErrNoPublicKeyAvailable is returned when no public root key is available to verify the
	// signatures on a biscuit's blocks.
	ErrNoPublicKeyAvailable = errors.New("biscuit: no public key available")
	// ErrUnknownPublicKey is returned when verifying a biscuit with the wrong public key
	ErrUnknownPublicKey = errors.New("biscuit: unknown public key")

	ErrInvalidSignature = crypto.ErrInvalidSignature

	ErrInvalidSignatureSize = errors.New("biscuit: invalid signature size")

	ErrInvalidKeySize = crypto.ErrInvalidKeySize

	ErrUnsupportedAlgorithm = crypto.ErrUnsupportedAlgorithm

	// Deprecated: use ErrUnsupportedAlgorithm.
	UnsupportedAlgorithm = ErrUnsupportedAlgorithm
)

type biscuitOptions struct {
	rng              io.Reader
	rootKeyID        *uint32
	nextKeyAlgorithm pb.PublicKey_Algorithm
}

type biscuitOption interface {
	applyToBiscuit(*biscuitOptions) error
}

func newBiscuit(root crypto.Signer, baseSymbols *datalog.SymbolTable, authority *Block, opts ...biscuitOption) (*Biscuit, error) {
	if root == nil {
		return nil, ErrNoPublicKeyAvailable
	}
	options := biscuitOptions{
		rng:              rand.Reader,
		nextKeyAlgorithm: root.Algorithm(),
	}
	for _, opt := range opts {
		if err := opt.applyToBiscuit(&options); err != nil {
			return nil, err
		}
	}

	symbols := baseSymbols.Clone()

	if !symbols.IsDisjoint(authority.symbols) {
		return nil, ErrSymbolTableOverlap
	}

	symbols.Extend(authority.symbols)
	publicKeys := publicKeyTable(nil).with(authority.publicKeys...)

	protoAuthority, err := tokenBlockToProtoBlock(authority, nil)
	if err != nil {
		return nil, err
	}
	marshalledAuthority, err := proto.Marshal(protoAuthority)
	if err != nil {
		return nil, err
	}

	signedBlock, proof, err := signBlock(root, options.nextKeyAlgorithm, marshalledAuthority, authority.version, nil, nil, options.rng)
	if err != nil {
		return nil, err
	}

	container := &pb.Biscuit{
		RootKeyId: options.rootKeyID,
		Authority: signedBlock,
		Proof:     proof,
	}

	return &Biscuit{
		authority:  authority,
		symbols:    symbols,
		publicKeys: publicKeys,
		container:  container,
	}, nil
}

func New(rng io.Reader, root ed25519.PrivateKey, baseSymbols *datalog.SymbolTable, authority *Block) (*Biscuit, error) {
	var opts []biscuitOption
	if rng != nil {
		opts = []biscuitOption{WithRNG(rng)}
	}
	signer, err := crypto.NewSigner(root)
	if err != nil {
		return nil, err
	}
	return newBiscuit(signer, baseSymbols, authority, opts...)
}

// Signature payload formats, selected per block by pb.SignedBlock.Version.
const (
	signatureVersionV0 uint32 = 0
	// signatureVersionV1 binds each signature to the previous one and tags
	// every field; required for third-party blocks, datalog v3.3 blocks and
	// any key that is not Ed25519.
	signatureVersionV1 uint32 = 1
)

// signatureVersion picks the payload format for a new block: v1 when the spec
// requires it, otherwise whatever the previous blocks use, so that tokens
// which only need v0 keep the same bytes as before.
func signatureVersion(signer, next crypto.Signer, blockVersion uint32, externalSignature *pb.ExternalSignature, previous ...*pb.SignedBlock) uint32 {
	if externalSignature != nil || blockVersion >= 6 {
		return signatureVersionV1
	}
	if signer.Algorithm() != pb.PublicKey_Ed25519 || next.Algorithm() != pb.PublicKey_Ed25519 {
		return signatureVersionV1
	}
	version := signatureVersionV0
	for _, block := range previous {
		version = max(version, block.GetVersion())
	}
	return version
}

// signBlock signs a serialized block with the key of the preceding block (or
// the root key for the authority block) and returns the block with the proof
// for the next block. The next key is generated with the given algorithm; each
// block in a token may use a different one. previous are the signed blocks this
// one is appended to, nil for the authority block. externalSignature is set
// for a third-party block and becomes part of the signed payload.
func signBlock(signer crypto.Signer, nextAlgorithm pb.PublicKey_Algorithm, marshalledBlock []byte, blockVersion uint32, externalSignature *pb.ExternalSignature, previous []*pb.SignedBlock, rng io.Reader) (*pb.SignedBlock, *pb.Proof, error) {
	next, err := crypto.GenerateSigner(nextAlgorithm, rng)
	if err != nil {
		return nil, nil, err
	}
	signedBlock := &pb.SignedBlock{
		Block: marshalledBlock,
		NextKey: &pb.PublicKey{
			Algorithm: next.Algorithm().Enum(),
			Key:       next.PublicKey(),
		},
		ExternalSignature: externalSignature,
	}
	if version := signatureVersion(signer, next, blockVersion, externalSignature, previous...); version != signatureVersionV0 {
		signedBlock.Version = &version
	}

	var previousSignature []byte
	if n := len(previous); n > 0 {
		previousSignature = previous[n-1].GetSignature()
	}
	signature, err := signer.Sign(blockSignaturePayload(signedBlock, previousSignature))
	if err != nil {
		return nil, nil, err
	}
	signedBlock.Signature = signature

	proof := &pb.Proof{
		Content: &pb.Proof_NextSecret{
			NextSecret: next.Secret(),
		},
	}
	return signedBlock, proof, nil
}

// blockSignaturePayload is the data signed for a block. previousSignature is
// nil for the authority block.
//
// v0: block [externalSig] alg(le u32) nextKey
// v1: "\0BLOCK\0\0VERSION\0" version(le u32) "\0PAYLOAD\0" block
//
//	"\0ALGORITHM\0" alg(le u32) "\0NEXTKEY\0" nextKey
//	["\0PREVSIG\0" previousSignature] ["\0EXTERNALSIG\0" externalSig]
func blockSignaturePayload(block *pb.SignedBlock, previousSignature []byte) []byte {
	algorithm := make([]byte, 4)
	binary.LittleEndian.PutUint32(algorithm, uint32(block.GetNextKey().GetAlgorithm()))
	externalSignature := block.GetExternalSignature().GetSignature()

	if block.GetVersion() == signatureVersionV0 {
		payload := make([]byte, 0, len(block.GetBlock())+len(externalSignature)+4+len(block.GetNextKey().GetKey()))
		payload = append(payload, block.GetBlock()...)
		payload = append(payload, externalSignature...)
		payload = append(payload, algorithm...)
		return append(payload, block.GetNextKey().GetKey()...)
	}

	version := make([]byte, 4)
	binary.LittleEndian.PutUint32(version, block.GetVersion())
	payload := []byte("\x00BLOCK\x00\x00VERSION\x00")
	payload = append(payload, version...)
	payload = append(payload, "\x00PAYLOAD\x00"...)
	payload = append(payload, block.GetBlock()...)
	payload = append(payload, "\x00ALGORITHM\x00"...)
	payload = append(payload, algorithm...)
	payload = append(payload, "\x00NEXTKEY\x00"...)
	payload = append(payload, block.GetNextKey().GetKey()...)
	if previousSignature != nil {
		payload = append(payload, "\x00PREVSIG\x00"...)
		payload = append(payload, previousSignature...)
	}
	if externalSignature != nil {
		payload = append(payload, "\x00EXTERNALSIG\x00"...)
		payload = append(payload, externalSignature...)
	}
	return payload
}

// externalSignaturePayload is the data a third party signs for its block:
// "\0EXTERNAL\0\0VERSION\0" version(le u32) "\0PAYLOAD\0" block "\0PREVSIG\0" previousSignature
// where previousSignature is the signature of the block it is appended to.
func externalSignaturePayload(marshalledBlock []byte, previousSignature []byte, version uint32) []byte {
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, version)
	payload := []byte("\x00EXTERNAL\x00\x00VERSION\x00")
	payload = append(payload, v...)
	payload = append(payload, "\x00PAYLOAD\x00"...)
	payload = append(payload, marshalledBlock...)
	payload = append(payload, "\x00PREVSIG\x00"...)
	return append(payload, previousSignature...)
}

// verifyExternalSignature checks the third-party signature of a block against
// the signature of the block before it.
func verifyExternalSignature(block *pb.SignedBlock, previousSignature []byte) error {
	ext := block.GetExternalSignature()
	verifier, err := crypto.ParseVerifier(ext.GetPublicKey().GetAlgorithm(), ext.GetPublicKey().GetKey())
	if err != nil {
		return err
	}
	if err := verifier.Verify(externalSignaturePayload(block.GetBlock(), previousSignature, block.GetVersion()), ext.GetSignature()); err != nil {
		return fmt.Errorf("biscuit: invalid external signature: %w", err)
	}
	return nil
}

// sealSignaturePayload is the data signed for the final proof. The spec
// defines only a v0 format: the v0 block payload of the last block, then
// its signature.
func sealSignaturePayload(lastBlock *pb.SignedBlock) []byte {
	v0 := &pb.SignedBlock{Block: lastBlock.GetBlock(), NextKey: lastBlock.GetNextKey()}
	return append(blockSignaturePayload(v0, nil), lastBlock.GetSignature()...)
}

// nextSigner decodes the private key of the proof with the algorithm of the last block.
func (b *Biscuit) nextSigner() (crypto.Signer, error) {
	secret := b.container.GetProof().GetNextSecret()
	if secret == nil {
		return nil, errors.New("biscuit: token is sealed")
	}
	return crypto.ParseSigner(b.lastSignedBlock().GetNextKey().GetAlgorithm(), secret)
}

func (b *Biscuit) lastSignedBlock() *pb.SignedBlock {
	if n := len(b.container.GetBlocks()); n > 0 {
		return b.container.Blocks[n-1]
	}
	return b.container.GetAuthority()
}

func (b *Biscuit) CreateBlock() BlockBuilder {
	return newBlockBuilder(b.symbols.Clone(), b.publicKeys)
}

func (b *Biscuit) Append(rng io.Reader, block *Block) (*Biscuit, error) {
	if b.container == nil {
		return nil, errors.New("biscuit: append failed, token is sealed")
	}

	signer, err := b.nextSigner()
	if err != nil {
		return nil, fmt.Errorf("biscuit: append failed: %w", err)
	}

	if !b.symbols.IsDisjoint(block.symbols) {
		return nil, ErrSymbolTableOverlap
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
	publicKeys := b.publicKeys.with(block.publicKeys...)

	// serialize and sign the new block
	protoBlock, err := tokenBlockToProtoBlock(block, b.publicKeys)
	if err != nil {
		return nil, err
	}
	marshalledBlock, err := proto.Marshal(protoBlock)
	if err != nil {
		return nil, err
	}

	if rng == nil {
		rng = rand.Reader
	}
	previous := append([]*pb.SignedBlock{b.container.Authority}, b.container.Blocks...)
	signedBlock, proof, err := signBlock(signer, signer.Algorithm(), marshalledBlock, block.version, nil, previous, rng)
	if err != nil {
		return nil, err
	}

	// clone container and append new marshalled block and public key
	container := &pb.Biscuit{
		Authority: b.container.Authority,
		Blocks:    append([]*pb.SignedBlock{}, b.container.Blocks...),
		Proof:     proof,
	}

	container.Blocks = append(container.Blocks, signedBlock)

	return &Biscuit{
		authority:  authority,
		blocks:     blocks,
		symbols:    symbols,
		publicKeys: publicKeys,
		container:  container,
	}, nil
}

func (b *Biscuit) Seal(rng io.Reader) (*Biscuit, error) {
	if b.container == nil {
		return nil, errors.New("biscuit: token is already sealed")
	}

	signer, err := b.nextSigner()
	if err != nil {
		return nil, fmt.Errorf("biscuit: seal failed: %w", err)
	}

	// clone biscuit fields and append new block
	authority := new(Block)
	*authority = *b.authority

	blocks := make([]*Block, len(b.blocks))
	for i, oldBlock := range b.blocks {
		blocks[i] = new(Block)
		*blocks[i] = *oldBlock
	}

	signature, err := signer.Sign(sealSignaturePayload(b.lastSignedBlock()))
	if err != nil {
		return nil, err
	}

	proof := &pb.Proof{
		Content: &pb.Proof_FinalSignature{
			FinalSignature: signature,
		},
	}

	// clone container and append new marshalled block and public key
	container := &pb.Biscuit{
		Authority: b.container.Authority,
		Blocks:    append([]*pb.SignedBlock{}, b.container.Blocks...),
		Proof:     proof,
	}

	symbols := b.symbols.Clone()

	return &Biscuit{
		authority:  authority,
		blocks:     blocks,
		symbols:    symbols,
		publicKeys: b.publicKeys,
		container:  container,
	}, nil
}

type (
	// A PublickKeyByIDProjection inspects an optional ID for a public key and returns the
	// corresponding public key, if any. If it doesn't recognize the ID or can't find the public
	// key, or no ID is supplied and there is no default public key available, it should return an
	// error satisfying errors.Is(err, ErrNoPublicKeyAvailable).
	//
	// The key is an ed25519.PublicKey or an *ecdsa.PublicKey on the P-256 curve.
	PublickKeyByIDProjection func(*uint32) (stdcrypto.PublicKey, error)
)

// WithSingularRootPublicKey supplies one public key to use as the root key with which to verify the
// signatures on a biscuit's blocks. The key is an ed25519.PublicKey or an *ecdsa.PublicKey on the
// P-256 curve.
func WithSingularRootPublicKey(key stdcrypto.PublicKey) PublickKeyByIDProjection {
	return func(*uint32) (stdcrypto.PublicKey, error) {
		return key, nil
	}
}

// WithRootPublicKeys supplies a mapping to public keys from their corresponding IDs, used to select
// which public key to use to verify the signatures on a biscuit's blocks based on the key ID
// embedded within the biscuit when it was created. If the biscuit has no key ID available, this
// function selects the optional default key instead. If no public key is available—whether for the
// biscuit's embedded key ID or a default key when no such ID is present—it returns
// [ErrNoPublicKeyAvailable].
func WithRootPublicKeys(keysByID map[uint32]ed25519.PublicKey, defaultKey *ed25519.PublicKey) PublickKeyByIDProjection {
	return func(id *uint32) (stdcrypto.PublicKey, error) {
		if id == nil {
			if defaultKey != nil {
				return *defaultKey, nil
			}
		} else if key, ok := keysByID[*id]; ok {
			return key, nil
		}
		return nil, ErrNoPublicKeyAvailable
	}
}

func (b *Biscuit) authorizerFor(root stdcrypto.PublicKey, opts ...AuthorizerOption) (Authorizer, error) {
	verifier, err := crypto.NewVerifier(root)
	if err != nil {
		return nil, err
	}
	if err := b.verifySignatures(verifier); err != nil {
		return nil, err
	}
	return NewVerifier(b, opts...)
}

// verifySignatures checks the chain of block signatures starting from the
// root key, then the proof: the next secret must match the last next key, or
// the final signature must verify with it.
func (b *Biscuit) verifySignatures(root crypto.Verifier) error {
	authority := b.container.GetAuthority()
	if err := root.Verify(blockSignaturePayload(authority, nil), authority.GetSignature()); err != nil {
		return err
	}
	current, err := crypto.ParseVerifier(authority.GetNextKey().GetAlgorithm(), authority.GetNextKey().GetKey())
	if err != nil {
		return err
	}
	previousSignature := authority.GetSignature()

	for _, block := range b.container.GetBlocks() {
		if err := current.Verify(blockSignaturePayload(block, previousSignature), block.GetSignature()); err != nil {
			return err
		}
		if block.GetExternalSignature() != nil {
			if err := verifyExternalSignature(block, previousSignature); err != nil {
				return err
			}
		}
		if current, err = crypto.ParseVerifier(block.GetNextKey().GetAlgorithm(), block.GetNextKey().GetKey()); err != nil {
			return err
		}
		previousSignature = block.GetSignature()
	}

	switch proof := b.container.GetProof().GetContent().(type) {
	case *pb.Proof_NextSecret:
		next, err := crypto.ParseSigner(current.Algorithm(), proof.NextSecret)
		if err != nil {
			return err
		}
		if !bytes.Equal(current.PublicKey(), next.PublicKey()) {
			return errors.New("biscuit: invalid last signature")
		}
	case *pb.Proof_FinalSignature:
		if err := current.Verify(sealSignaturePayload(b.lastSignedBlock()), proof.FinalSignature); err != nil {
			return errors.New("biscuit: invalid last signature")
		}
	default:
		return errors.New("biscuit: cannot find proof")
	}
	return nil
}

// AuthorizerFor selects from the supplied source a root public key to use to verify the signatures
// on the biscuit's blocks, returning an error satisfying errors.Is(err, ErrNoPublicKeyAvailable) if
// no such public key is available. If the signatures are valid, it creates an [Authorizer], which
// can then test the authorization policies and accept or refuse the request.
func (b *Biscuit) AuthorizerFor(keySource PublickKeyByIDProjection, opts ...AuthorizerOption) (Authorizer, error) {
	if keySource == nil {
		return nil, errors.New("root public key source must not be nil")
	}
	rootPublicKey, err := keySource(b.RootKeyID())
	if err != nil {
		return nil, fmt.Errorf("choosing root public key: %w", err)
	}
	if rootPublicKey == nil {
		return nil, ErrNoPublicKeyAvailable
	}
	if key, ok := rootPublicKey.(ed25519.PublicKey); ok && len(key) == 0 {
		return nil, ErrNoPublicKeyAvailable
	}
	return b.authorizerFor(rootPublicKey, opts...)
}

// TODO: Add "Deprecated" note to the "(*Biscuit).Authorizer" method, recommending use of
// "(*Biscuit).AuthorizerFor" instead. Wait until after we release the module with the latter
// available, per https://go.dev/wiki/Deprecated.

// Authorizer checks the signature and creates an [Authorizer]. The Authorizer can then test the
// authorizaion policies and accept or refuse the request. The root key is an ed25519.PublicKey or
// an *ecdsa.PublicKey on the P-256 curve.
func (b *Biscuit) Authorizer(root stdcrypto.PublicKey, opts ...AuthorizerOption) (Authorizer, error) {
	return b.authorizerFor(root, opts...)
}

func (b *Biscuit) Checks() [][]datalog.Check {
	result := make([][]datalog.Check, 0, len(b.blocks)+1)
	result = append(result, b.authority.checks)
	for _, block := range b.blocks {
		result = append(result, block.checks)
	}
	return result
}

func (b *Biscuit) GetContext() string {
	if b == nil || b.authority == nil {
		return ""
	}

	return b.authority.context
}

func (b *Biscuit) Serialize() ([]byte, error) {
	return proto.Marshal(b.container)
}

var ErrFactNotFound = errors.New("biscuit: fact not found")

// GetBlockID returns the first block index containing a fact
// starting from the authority block and then each block in the order they were added.
// ErrFactNotFound is returned when no block contains the fact.
func (b *Biscuit) GetBlockID(fact Fact) (int, error) {
	// don't store symbols from searched fact in the verifier table
	symbols := b.symbols.Clone()
	datalogFact := fact.Predicate.convert(symbols)

	for _, f := range *b.authority.facts {
		if f.Equal(datalogFact) {
			return 0, nil
		}
	}

	for i, b := range b.blocks {
		for _, f := range *b.facts {
			if f.Equal(datalogFact) {
				return i + 1, nil
			}
		}
	}

	return 0, ErrFactNotFound
}

/*
// SHA256Sum returns a hash of `count` biscuit blocks + the authority block
// along with their respective keys.
func (b *Biscuit) SHA256Sum(count int) ([]byte, error) {
	if count < 0 {
		return nil, fmt.Errorf("biscuit: invalid count,  %d < 0 ", count)
	}
	if g, w := count, len(b.container.Blocks); g > w {
		return nil, fmt.Errorf("biscuit: invalid count,  %d > %d", g, w)
	}

	h := sha256.New()
	// write the authority block and the root key
	if _, err := h.Write(b.container.Authority); err != nil {
		return nil, err
	}
	if _, err := h.Write(b.container.Keys[0]); err != nil {
		return nil, err
	}

	for _, block := range b.container.Blocks[:count] {
		if _, err := h.Write(block); err != nil {
			return nil, err
		}
	}
	for _, key := range b.container.Keys[:count+1] { // +1 to skip the root key
		if _, err := h.Write(key); err != nil {
			return nil, err
		}
	}

	return h.Sum(nil), nil
}*/

func (b *Biscuit) BlockCount() int {
	return len(b.container.Blocks)
}

func (b *Biscuit) RootKeyID() *uint32 {
	return b.container.RootKeyId
}

func (b *Biscuit) String() string {
	blocks := make([]string, len(b.blocks))
	for i, block := range b.blocks {
		blocks[i] = block.String(block.symbolTable(b.symbols))
	}

	return fmt.Sprintf(`
Biscuit {
	symbols: %+q
	authority: %s
	blocks: %v
}`,
		*b.symbols,
		b.authority.String(b.symbols),
		blocks,
	)
}

func (b *Biscuit) Code() []string {
	blocks := make([]string, len(b.blocks))
	for i, block := range b.blocks {
		blocks[i] = block.Code(block.symbolTable(b.symbols))
	}
	return blocks
}

func (b *Biscuit) RevocationIds() [][]byte {
	result := make([][]byte, 0, len(b.blocks)+1)
	result = append(result, b.container.Authority.Signature)
	for _, block := range b.container.Blocks {
		result = append(result, block.Signature)
	}
	return result
}
