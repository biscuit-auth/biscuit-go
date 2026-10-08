// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	stdcrypto "crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/eclipse-biscuit/biscuit-go/v2/internal/crypto"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
	"google.golang.org/protobuf/proto"
)

// A third-party block is a block signed by a party that does not hold the
// token. The holder sends a ThirdPartyBlockRequest, the third party answers
// with a ThirdPartyBlockContents built from its own key, and the holder
// appends it with Biscuit.AppendThirdPartyBlock. Facts of such a block are
// visible to rules that trust the third party's key (`trusting <key>`).

// ThirdPartyBlockRequest is what a third party needs to sign a block for a
// token: the signature of the token's last block, which binds the new block
// to that token.
type ThirdPartyBlockRequest struct {
	previousSignature []byte
}

// ThirdPartyRequest creates the request for a third-party block to append to
// this token.
func (b *Biscuit) ThirdPartyRequest() (*ThirdPartyBlockRequest, error) {
	if b.container.GetProof().GetNextSecret() == nil {
		return nil, errors.New("biscuit: token is sealed")
	}
	return &ThirdPartyBlockRequest{previousSignature: b.lastSignedBlock().GetSignature()}, nil
}

func (r *ThirdPartyBlockRequest) Serialize() ([]byte, error) {
	return proto.Marshal(&pb.ThirdPartyBlockRequest{PreviousSignature: r.previousSignature})
}

func UnmarshalThirdPartyBlockRequest(serialized []byte) (*ThirdPartyBlockRequest, error) {
	req := new(pb.ThirdPartyBlockRequest)
	if err := proto.Unmarshal(serialized, req); err != nil {
		return nil, err
	}
	// Set only by implementations of the deprecated v0 flow.
	if req.LegacyPreviousKey != nil || len(req.LegacyPublicKeys) > 0 {
		return nil, errors.New("biscuit: third-party block request uses the legacy format")
	}
	if len(req.PreviousSignature) == 0 {
		return nil, errors.New("biscuit: third-party block request without previous signature")
	}
	return &ThirdPartyBlockRequest{previousSignature: req.PreviousSignature}, nil
}

// NewThirdPartyBlockBuilder creates the builder for a third-party block,
// which has its own symbol table and does not know the token's.
func NewThirdPartyBlockBuilder() BlockBuilder {
	return NewBlockBuilder(defaultSymbolTable.Clone())
}

// CreateBlock builds and signs the block with the third party's key: an
// ed25519.PrivateKey or an *ecdsa.PrivateKey on the P-256 curve. The builder
// must come from NewThirdPartyBlockBuilder.
func (r *ThirdPartyBlockRequest) CreateBlock(key stdcrypto.Signer, builder BlockBuilder) (*ThirdPartyBlockContents, error) {
	signer, err := crypto.NewSigner(key)
	if err != nil {
		return nil, err
	}
	if bb, ok := builder.(*blockBuilder); !ok || bb.symbolsStart != defaultSymbolTable.Len() || len(bb.publicKeys) > 0 {
		return nil, errors.New("biscuit: a third-party block must be built with NewThirdPartyBlockBuilder")
	}

	block := builder.Build()
	block.version = max(block.version, blockVersion3_2)
	protoBlock, err := tokenBlockToProtoBlock(block, nil)
	if err != nil {
		return nil, err
	}
	payload, err := proto.Marshal(protoBlock)
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(externalSignaturePayload(payload, r.previousSignature, signatureVersionV1))
	if err != nil {
		return nil, err
	}

	return &ThirdPartyBlockContents{
		payload: payload,
		externalSignature: &pb.ExternalSignature{
			Signature: signature,
			PublicKey: &pb.PublicKey{
				Algorithm: signer.Algorithm().Enum(),
				Key:       signer.PublicKey(),
			},
		},
	}, nil
}

// ThirdPartyBlockContents is a block serialized and signed by a third party,
// to append to the token the request came from.
type ThirdPartyBlockContents struct {
	payload           []byte
	externalSignature *pb.ExternalSignature
}

func (c *ThirdPartyBlockContents) Serialize() ([]byte, error) {
	return proto.Marshal(&pb.ThirdPartyBlockContents{Payload: c.payload, ExternalSignature: c.externalSignature})
}

func UnmarshalThirdPartyBlockContents(serialized []byte) (*ThirdPartyBlockContents, error) {
	contents := new(pb.ThirdPartyBlockContents)
	if err := proto.Unmarshal(serialized, contents); err != nil {
		return nil, err
	}
	if contents.ExternalSignature == nil || len(contents.Payload) == 0 {
		return nil, errors.New("biscuit: incomplete third-party block contents")
	}
	return &ThirdPartyBlockContents{payload: contents.Payload, externalSignature: contents.ExternalSignature}, nil
}

// PublicKey is the key the third party signed with.
func (c *ThirdPartyBlockContents) PublicKey() (PublicKey, error) {
	return protoPublicKeyToTokenPublicKey(c.externalSignature.GetPublicKey())
}

// AppendThirdPartyBlock appends a block signed by a third party. The block
// must have been made for this token (from its ThirdPartyRequest) and signed
// by expectedKey, an ed25519.PublicKey or an *ecdsa.PublicKey. A nil rng
// uses crypto/rand.
func (b *Biscuit) AppendThirdPartyBlock(rng io.Reader, expectedKey stdcrypto.PublicKey, contents *ThirdPartyBlockContents) (*Biscuit, error) {
	if rng == nil {
		rng = rand.Reader
	}
	signer, err := b.nextSigner()
	if err != nil {
		return nil, fmt.Errorf("biscuit: append failed: %w", err)
	}

	expected, err := PublicKeyFrom(expectedKey)
	if err != nil {
		return nil, err
	}
	provided, err := contents.PublicKey()
	if err != nil {
		return nil, err
	}
	if !expected.Equal(provided) {
		return nil, fmt.Errorf("biscuit: third-party block signed by %s, expected %s", provided, expected)
	}

	previous := append([]*pb.SignedBlock{b.container.Authority}, b.container.Blocks...)
	previousSignature := previous[len(previous)-1].GetSignature()
	candidate := &pb.SignedBlock{Block: contents.payload, ExternalSignature: contents.externalSignature, Version: proto.Uint32(signatureVersionV1)}
	if err := verifyExternalSignature(candidate, previousSignature); err != nil {
		return nil, err
	}

	pbBlock := new(pb.Block)
	if err := proto.Unmarshal(contents.payload, pbBlock); err != nil {
		return nil, err
	}
	block, err := thirdPartyBlock(pbBlock, contents.externalSignature)
	if err != nil {
		return nil, err
	}

	signedBlock, proof, err := signBlock(signer, signer.Algorithm(), contents.payload, block.version, contents.externalSignature, previous, rng)
	if err != nil {
		return nil, err
	}

	authority := new(Block)
	*authority = *b.authority
	blocks := make([]*Block, len(b.blocks)+1)
	for i, oldBlock := range b.blocks {
		blocks[i] = new(Block)
		*blocks[i] = *oldBlock
	}
	blocks[len(b.blocks)] = block

	container := &pb.Biscuit{
		RootKeyId: b.container.RootKeyId,
		Authority: b.container.Authority,
		Blocks:    append(append([]*pb.SignedBlock{}, b.container.Blocks...), signedBlock),
		Proof:     proof,
	}

	// The token's symbol and key tables are not extended by a third-party block.
	return &Biscuit{
		authority:  authority,
		blocks:     blocks,
		symbols:    b.symbols.Clone(),
		publicKeys: b.publicKeys,
		container:  container,
	}, nil
}
