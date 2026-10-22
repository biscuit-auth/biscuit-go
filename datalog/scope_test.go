// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScopeString(t *testing.T) {
	key := PublicKey{Algorithm: AlgorithmEd25519, Key: []byte{0xac, 0xdd}}
	require.Equal(t, "authority", Scope{Kind: ScopeAuthority}.String())
	require.Equal(t, "previous", Scope{Kind: ScopePrevious}.String())
	require.Equal(t, "ed25519/acdd", Scope{Kind: ScopePublicKey, PublicKey: key}.String())
	require.Equal(t, "secp256r1/acdd", PublicKey{Algorithm: AlgorithmSecp256r1, Key: []byte{0xac, 0xdd}}.String())
	require.Equal(t, "", ScopesString(nil))
	require.Equal(t, " trusting previous, ed25519/acdd", ScopesString([]Scope{{Kind: ScopePrevious}, {Kind: ScopePublicKey, PublicKey: key}}))
}

func TestTrustedOriginsFromScopes(t *testing.T) {
	key := PublicKey{Algorithm: AlgorithmEd25519, Key: []byte{0x01}}
	other := PublicKey{Algorithm: AlgorithmEd25519, Key: []byte{0x02}}
	blocksByKey := map[string][]BlockID{key.String(): {1, 3}}

	for _, tc := range []struct {
		desc     string
		scopes   []Scope
		defaults TrustedOrigins
		current  BlockID
		want     TrustedOrigins
	}{
		{"no scopes: defaults plus the block and the authorizer", nil, DefaultTrustedOrigins(), 2, NewTrustedOrigins(0, 2, AuthorizerBlockID)},
		{"no scopes inherits block scopes", nil, NewTrustedOrigins(1, 2, AuthorizerBlockID), 2, NewTrustedOrigins(1, 2, AuthorizerBlockID)},
		{"authority", []Scope{{Kind: ScopeAuthority}}, NewTrustedOrigins(5), 2, NewTrustedOrigins(0, 2, AuthorizerBlockID)},
		{"previous", []Scope{{Kind: ScopePrevious}}, DefaultTrustedOrigins(), 2, NewTrustedOrigins(0, 1, 2, AuthorizerBlockID)},
		{"previous from the authorizer", []Scope{{Kind: ScopePrevious}}, DefaultTrustedOrigins(), AuthorizerBlockID, NewTrustedOrigins(AuthorizerBlockID)},
		{"public key with blocks", []Scope{{Kind: ScopePublicKey, PublicKey: key}}, DefaultTrustedOrigins(), 2, NewTrustedOrigins(1, 2, 3, AuthorizerBlockID)},
		{"public key without blocks", []Scope{{Kind: ScopePublicKey, PublicKey: other}}, DefaultTrustedOrigins(), 2, NewTrustedOrigins(2, AuthorizerBlockID)},
		{"combined", []Scope{{Kind: ScopeAuthority}, {Kind: ScopePublicKey, PublicKey: key}}, DefaultTrustedOrigins(), 4, NewTrustedOrigins(0, 1, 3, 4, AuthorizerBlockID)},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			require.Equal(t, tc.want, TrustedOriginsFromScopes(tc.scopes, tc.defaults, tc.current, blocksByKey))
		})
	}
}
