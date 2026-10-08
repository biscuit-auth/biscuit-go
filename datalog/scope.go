// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
)

// Algorithm of a public key, numbered as in the schema.
type Algorithm int32

const (
	AlgorithmEd25519   Algorithm = 0
	AlgorithmSecp256r1 Algorithm = 1
)

func (a Algorithm) String() string {
	switch a {
	case AlgorithmEd25519:
		return "ed25519"
	case AlgorithmSecp256r1:
		return "secp256r1"
	default:
		return fmt.Sprintf("algorithm(%d)", int32(a))
	}
}

// PublicKey is a public key as it appears in a scope: the algorithm and the
// key bytes in the encoding of the spec.
type PublicKey struct {
	Algorithm Algorithm
	Key       []byte
}

func (k PublicKey) Equal(other PublicKey) bool {
	return k.Algorithm == other.Algorithm && bytes.Equal(k.Key, other.Key)
}

// String prints the key as the datalog syntax does: algorithm/hex.
func (k PublicKey) String() string {
	return k.Algorithm.String() + "/" + hex.EncodeToString(k.Key)
}

// ScopeKind is the kind of a scope entry in a `trusting` clause.
type ScopeKind byte

const (
	// ScopeAuthority trusts the authority block.
	ScopeAuthority ScopeKind = iota
	// ScopePrevious trusts every block up to the current one.
	ScopePrevious
	// ScopePublicKey trusts the third-party blocks signed by PublicKey.
	ScopePublicKey
)

// Scope is one entry of a `trusting` clause. A rule with scopes reads the
// facts of the authorizer, of its own block and of the blocks its scopes
// designate; without scopes it inherits the scopes of its block, or the
// defaults.
type Scope struct {
	Kind      ScopeKind
	PublicKey PublicKey
}

func (s Scope) Equal(other Scope) bool {
	return s.Kind == other.Kind && s.PublicKey.Equal(other.PublicKey)
}

func (s Scope) String() string {
	switch s.Kind {
	case ScopeAuthority:
		return "authority"
	case ScopePrevious:
		return "previous"
	case ScopePublicKey:
		return s.PublicKey.String()
	default:
		return fmt.Sprintf("scope(%d)", s.Kind)
	}
}

// ScopesString prints a `trusting` clause, empty when there are no scopes.
func ScopesString(scopes []Scope) string {
	if len(scopes) == 0 {
		return ""
	}
	strs := make([]string, len(scopes))
	for i, s := range scopes {
		strs[i] = s.String()
	}
	return " trusting " + strings.Join(strs, ", ")
}

// TrustedOriginsFromScopes resolves the scopes of a rule, check or policy
// from block current into the blocks it may read facts from. Without scopes
// the defaults apply, plus the current block and the authorizer. With
// scopes, only the authorizer, the current block and what the scopes
// designate are trusted: the authority for ScopeAuthority, blocks 0 to
// current for ScopePrevious, and for ScopePublicKey the blocks of
// blocksByKey, keyed by PublicKey.String(), signed by that key.
func TrustedOriginsFromScopes(scopes []Scope, defaults TrustedOrigins, current BlockID, blocksByKey map[string][]BlockID) TrustedOrigins {
	if len(scopes) == 0 {
		return defaults.With(current, AuthorizerBlockID)
	}

	origins := NewOrigin(AuthorizerBlockID, current)
	for _, scope := range scopes {
		switch scope.Kind {
		case ScopeAuthority:
			origins = origins.With(0)
		case ScopePrevious:
			if current != AuthorizerBlockID {
				previous := make([]BlockID, 0, current+1)
				for i := BlockID(0); i <= current; i++ {
					previous = append(previous, i)
				}
				origins = origins.With(previous...)
			}
		case ScopePublicKey:
			origins = origins.With(blocksByKey[scope.PublicKey.String()]...)
		}
	}
	return TrustedOrigins(origins)
}
