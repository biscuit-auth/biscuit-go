// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/stretchr/testify/require"
)

// The flow of the spec: the holder issues a request, the third party signs a
// block for it, the holder appends it; rules see its facts only when they
// trust the third party's key.
func TestThirdPartyBlock(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	for _, tc := range []struct {
		name    string
		private stdcrypto.Signer
		public  stdcrypto.PublicKey
	}{
		{"ed25519", edPriv, edPub},
		{"secp256r1", ecKey, &ecKey.PublicKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
			thirdPartyPublic := tc.public
			trust, err := TrustingPublicKey(thirdPartyPublic)
			require.NoError(t, err)

			// The authority block requires a fact from the third party.
			builder := NewBuilder(privateRoot)
			require.NoError(t, builder.AddAuthorityFact(Fact{Predicate{Name: "right", IDs: []Term{String("read")}}}))
			require.NoError(t, builder.AddAuthorityCheck(Check{Queries: []Rule{{
				Head:   Predicate{Name: "query"},
				Body:   []Predicate{{Name: "group", IDs: []Term{String("admin")}}},
				Scopes: []Scope{trust},
			}}}))
			token, err := builder.Build()
			require.NoError(t, err)

			// Holder side: the request travels serialized.
			request, err := token.ThirdPartyRequest()
			require.NoError(t, err)
			requestBytes, err := request.Serialize()
			require.NoError(t, err)

			// Third party side: a block with its own symbols, signed with its key.
			request, err = UnmarshalThirdPartyBlockRequest(requestBytes)
			require.NoError(t, err)
			blockBuilder := NewThirdPartyBlockBuilder()
			require.NoError(t, blockBuilder.AddFact(Fact{Predicate{Name: "group", IDs: []Term{String("admin")}}}))
			require.NoError(t, blockBuilder.AddCheck(Check{Queries: []Rule{{
				Head: Predicate{Name: "query"},
				Body: []Predicate{{Name: "right", IDs: []Term{String("read")}}},
			}}}))
			contents, err := request.CreateBlock(tc.private, blockBuilder)
			require.NoError(t, err)
			contentsBytes, err := contents.Serialize()
			require.NoError(t, err)

			// Holder side again.
			contents, err = UnmarshalThirdPartyBlockContents(contentsBytes)
			require.NoError(t, err)
			appended, err := token.AppendThirdPartyBlock(nil, thirdPartyPublic, contents)
			require.NoError(t, err)
			require.Equal(t, token.symbols, appended.symbols, "a third-party block must not extend the token's symbol table")
			require.EqualValues(t, 5, appended.blocks[0].version)
			require.NotNil(t, appended.blocks[0].externalKey)

			deser, err := Unmarshal(mustSerialize(t, appended))
			require.NoError(t, err)
			require.Contains(t, deser.Code()[0], `group("admin")`)

			ab, err := deser.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
			require.NoError(t, err)
			ab.AddPolicy(DefaultAllowPolicy)
			require.NoError(t, ab.Authorize())
			require.Contains(t, ab.PrintWorld(), "// origin: [1]\ngroup(\"admin\");")

			// A policy trusting the key sees the third-party fact; without it, not.
			query := Rule{Head: Predicate{Name: "query"}, Body: []Predicate{{Name: "group", IDs: []Term{String("admin")}}}}
			ab, err = deser.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
			require.NoError(t, err)
			ab.AddPolicy(Policy{Kind: PolicyKindAllow, Queries: []Rule{query}})
			require.ErrorIs(t, ab.Authorize(), ErrNoMatchingPolicy)

			trusted := query
			trusted.Scopes = []Scope{trust}
			ab, err = deser.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
			require.NoError(t, err)
			ab.AddPolicy(Policy{Kind: PolicyKindAllow, Queries: []Rule{trusted}})
			require.NoError(t, ab.Authorize())

			// The block is bound to the token it was requested for.
			otherToken, err := NewBuilder(privateRoot).Build()
			require.NoError(t, err)
			_, err = otherToken.AppendThirdPartyBlock(nil, thirdPartyPublic, contents)
			require.ErrorContains(t, err, "invalid external signature")

			// And to the key the holder expects.
			otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
			_, err = token.AppendThirdPartyBlock(nil, otherPub, contents)
			require.ErrorContains(t, err, "third-party block signed by")

			// A builder made from the token would use the token's symbol table.
			_, err = request.CreateBlock(tc.private, token.CreateBlock())
			require.ErrorContains(t, err, "NewThirdPartyBlockBuilder")

			// A tampered payload fails verification.
			tampered := *contents
			tampered.payload = append([]byte{}, contents.payload...)
			tampered.payload[len(tampered.payload)-1] ^= 0xff
			_, err = token.AppendThirdPartyBlock(nil, thirdPartyPublic, &tampered)
			require.Error(t, err)
		})
	}
}

// A third-party block's public keys and symbols are its own: the same key
// in the token table and in the block table resolves independently.
func TestThirdPartyBlockIsolatedTables(t *testing.T) {
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rand.Reader)
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	trust1, _ := TrustingPublicKey(pub1)
	trust2, _ := TrustingPublicKey(pub2)

	builder := NewBuilder(privateRoot)
	require.NoError(t, builder.AddAuthorityFact(Fact{Predicate{Name: "query", IDs: []Term{Integer(0)}}}))
	token, err := builder.Build()
	require.NoError(t, err)

	appendThirdParty := func(token *Biscuit, priv ed25519.PrivateKey, pub ed25519.PublicKey, block func(BlockBuilder)) *Biscuit {
		request, err := token.ThirdPartyRequest()
		require.NoError(t, err)
		bb := NewThirdPartyBlockBuilder()
		block(bb)
		contents, err := request.CreateBlock(priv, bb)
		require.NoError(t, err)
		next, err := token.AppendThirdPartyBlock(nil, pub, contents)
		require.NoError(t, err)
		return next
	}

	// Block 1 (key 1): query(1), and a rule trusting key 2 that joins with block 2.
	token = appendThirdParty(token, priv1, pub1, func(bb BlockBuilder) {
		require.NoError(t, bb.AddFact(Fact{Predicate{Name: "query", IDs: []Term{Integer(1)}}}))
		require.NoError(t, bb.AddRule(Rule{
			Head:   Predicate{Name: "query", IDs: []Term{Integer(1), Integer(2)}},
			Body:   []Predicate{{Name: "query", IDs: []Term{Integer(1)}}, {Name: "query", IDs: []Term{Integer(2)}}},
			Scopes: []Scope{trust2},
		}))
	})
	// Block 2 (key 2): query(2), with a check trusting key 1.
	token = appendThirdParty(token, priv2, pub2, func(bb BlockBuilder) {
		require.NoError(t, bb.AddFact(Fact{Predicate{Name: "query", IDs: []Term{Integer(2)}}}))
		require.NoError(t, bb.AddCheck(Check{Queries: []Rule{{
			Head:   Predicate{Name: "query"},
			Body:   []Predicate{{Name: "query", IDs: []Term{Integer(1)}}},
			Scopes: []Scope{trust1},
		}}}))
	})
	// Block 3 (first party): a check trusting both keys.
	block3 := token.CreateBlock()
	require.NoError(t, block3.AddCheck(Check{Queries: []Rule{{
		Head:   Predicate{Name: "query"},
		Body:   []Predicate{{Name: "query", IDs: []Term{Integer(1), Integer(2)}}},
		Scopes: []Scope{trust1, trust2},
	}}}))
	token, err = token.Append(rand.Reader, block3.Build())
	require.NoError(t, err)
	require.Equal(t, publicKeyTable{trust1.PublicKey, trust2.PublicKey}, token.publicKeys)

	deser, err := Unmarshal(mustSerialize(t, token))
	require.NoError(t, err)
	require.Equal(t, []datalog.PublicKey{trust2.PublicKey}, deser.blocks[0].publicKeys)
	require.Equal(t, []datalog.PublicKey{trust1.PublicKey}, deser.blocks[1].publicKeys)
	require.Equal(t, []datalog.PublicKey{trust1.PublicKey, trust2.PublicKey}, deser.blocks[2].publicKeys)

	ab, err := deser.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
	require.NoError(t, err)
	ab.AddPolicy(DefaultAllowPolicy)
	require.NoError(t, ab.Authorize())
	require.Contains(t, ab.PrintWorld(), "// origin: [1, 2]\nquery(1, 2);")
}
