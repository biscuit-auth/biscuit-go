// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/eclipse-biscuit/biscuit-go/v2/internal/crypto"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
	"github.com/stretchr/testify/require"
)

// A token built from an ECDSA root key, appended, sealed and verified.
func TestBiscuitSecp256r1(t *testing.T) {
	privateRoot, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	builder := NewBuilderWithSigner(privateRoot)
	require.NoError(t, builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file1"), String("read")}},
	}))
	b1, err := builder.Build()
	require.NoError(t, err)

	b1deser, err := Unmarshal(mustSerialize(t, b1))
	require.NoError(t, err)

	// Non-Ed25519 keys require the v1 signature payload.
	require.EqualValues(t, 1, b1deser.container.Authority.GetVersion())
	require.Equal(t, pb.PublicKey_SECP256R1, b1deser.container.Authority.GetNextKey().GetAlgorithm())

	block := b1deser.CreateBlock()
	require.NoError(t, block.AddFact(Fact{Predicate: Predicate{Name: "appended", IDs: []Term{Integer(1)}}}))
	b2, err := b1deser.Append(rand.Reader, block.Build())
	require.NoError(t, err)

	b2deser, err := Unmarshal(mustSerialize(t, b2))
	require.NoError(t, err)
	_, err = b2deser.AuthorizerFor(WithSingularRootPublicKey(&privateRoot.PublicKey))
	require.NoError(t, err)

	sealed, err := b2deser.Seal(rand.Reader)
	require.NoError(t, err)
	sealedDeser, err := Unmarshal(mustSerialize(t, sealed))
	require.NoError(t, err)
	_, err = sealedDeser.AuthorizerFor(WithSingularRootPublicKey(&privateRoot.PublicKey))
	require.NoError(t, err)

	otherRoot, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = b2deser.Authorizer(&otherRoot.PublicKey)
	require.ErrorIs(t, err, ErrInvalidSignature)

	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, err = b2deser.Authorizer(edPub)
	require.ErrorIs(t, err, ErrInvalidSignature)
}

// Ed25519-only tokens keep the v0 payload, so they are byte compatible with
// tokens produced before signature payload v1 existed.
func TestBiscuitSignatureVersionEd25519(t *testing.T) {
	_, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
	b1, err := NewBuilder(privateRoot).Build()
	require.NoError(t, err)
	require.EqualValues(t, 0, b1.container.Authority.GetVersion())

	b2, err := b1.Append(rand.Reader, b1.CreateBlock().Build())
	require.NoError(t, err)
	require.EqualValues(t, 0, b2.container.Blocks[0].GetVersion())
}

func TestBuilderUnsupportedRootKey(t *testing.T) {
	_, err := NewBuilderWithSigner(nil).Build()
	require.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

// Each block verifies with the previous block's key; a tampered previous
// signature breaks a v1 block even when its own signature is intact.
func TestBiscuitV1PreviousSignatureBinding(t *testing.T) {
	privateRoot, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	b1, err := NewBuilderWithSigner(privateRoot).Build()
	require.NoError(t, err)
	b2, err := b1.Append(rand.Reader, b1.CreateBlock().Build())
	require.NoError(t, err)

	_, err = b2.Authorizer(&privateRoot.PublicKey)
	require.NoError(t, err)

	// Re-sign the authority with the root key over the same content: the
	// signature stays valid on its own, but block 1 bound the old one.
	authority := b2.container.Authority
	rootSigner, err := crypto.NewSigner(privateRoot)
	require.NoError(t, err)
	resigned, err := rootSigner.Sign(blockSignaturePayload(authority, nil))
	require.NoError(t, err)
	require.NotEqual(t, authority.Signature, resigned)
	authority.Signature = resigned

	_, err = b2.Authorizer(&privateRoot.PublicKey)
	require.ErrorIs(t, err, ErrInvalidSignature)
}

func mustSerialize(t *testing.T, b *Biscuit) []byte {
	t.Helper()
	ser, err := b.Serialize()
	require.NoError(t, err)
	return ser
}
