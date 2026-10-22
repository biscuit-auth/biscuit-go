// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
	"github.com/stretchr/testify/require"
)

func TestRoundTrip(t *testing.T) {
	for _, alg := range []pb.PublicKey_Algorithm{pb.PublicKey_Ed25519, pb.PublicKey_SECP256R1} {
		t.Run(alg.String(), func(t *testing.T) {
			signer, err := GenerateSigner(alg, rand.Reader)
			require.NoError(t, err)
			require.Equal(t, alg, signer.Algorithm())

			payload := []byte("payload")
			sig, err := signer.Sign(payload)
			require.NoError(t, err)

			// The public key travels in pb.PublicKey, the secret in pb.Proof.
			verifier, err := ParseVerifier(alg, signer.PublicKey())
			require.NoError(t, err)
			require.NoError(t, verifier.Verify(payload, sig))
			require.ErrorIs(t, verifier.Verify([]byte("other"), sig), ErrInvalidSignature)

			parsed, err := ParseSigner(alg, signer.Secret())
			require.NoError(t, err)
			require.Equal(t, signer.PublicKey(), parsed.PublicKey())
			require.Len(t, signer.Secret(), 32)
		})
	}
}

func TestNewSignerVerifier(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		priv crypto.Signer
		pub  crypto.PublicKey
		alg  pb.PublicKey_Algorithm
	}{
		{"ed25519", edPriv, edPub, pb.PublicKey_Ed25519},
		{"secp256r1", ecPriv, &ecPriv.PublicKey, pb.PublicKey_SECP256R1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := NewSigner(tc.priv)
			require.NoError(t, err)
			verifier, err := NewVerifier(tc.pub)
			require.NoError(t, err)
			require.Equal(t, tc.alg, signer.Algorithm())
			require.Equal(t, tc.alg, verifier.Algorithm())
			require.Equal(t, signer.PublicKey(), verifier.PublicKey())

			sig, err := signer.Sign([]byte("payload"))
			require.NoError(t, err)
			require.NoError(t, verifier.Verify([]byte("payload"), sig))
		})
	}

	_, err = NewSigner(nil)
	require.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	_, err = NewVerifier([]byte("not a key"))
	require.ErrorIs(t, err, ErrInvalidKeySize)
	fromBytes, err := NewVerifier([]byte(edPub))
	require.NoError(t, err)
	require.Equal(t, pb.PublicKey_Ed25519, fromBytes.Algorithm())
	_, err = ParseVerifier(pb.PublicKey_SECP256R1, edPub)
	require.ErrorIs(t, err, ErrInvalidKeySize)
}
