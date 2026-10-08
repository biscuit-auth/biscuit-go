// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	stdcrypto "crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/internal/crypto"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
)

// Scope is one entry of a `trusting` clause on a rule, check, policy or
// block. See datalog.Scope.
type Scope = datalog.Scope

// PublicKey is a public key as written in a scope. Build one from a crypto
// key with PublicKeyFrom.
type PublicKey = datalog.PublicKey

const (
	ScopeAuthority = datalog.ScopeAuthority
	ScopePrevious  = datalog.ScopePrevious
	ScopePublicKey = datalog.ScopePublicKey
)

// PublicKeyFrom encodes an ed25519.PublicKey or an *ecdsa.PublicKey on the
// P-256 curve as a scope public key.
func PublicKeyFrom(key stdcrypto.PublicKey) (PublicKey, error) {
	verifier, err := crypto.NewVerifier(key)
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey{Algorithm: datalog.Algorithm(verifier.Algorithm()), Key: verifier.PublicKey()}, nil
}

// ParsePublicKey reads a key in the datalog syntax, algorithm/hex, where
// algorithm is ed25519 or secp256r1.
func ParsePublicKey(s string) (PublicKey, error) {
	algorithm, encoded, ok := strings.Cut(s, "/")
	if !ok {
		return PublicKey{}, fmt.Errorf("biscuit: invalid public key %q: expected algorithm/hex", s)
	}
	var alg pb.PublicKey_Algorithm
	switch algorithm {
	case "ed25519":
		alg = pb.PublicKey_Ed25519
	case "secp256r1":
		alg = pb.PublicKey_SECP256R1
	default:
		return PublicKey{}, fmt.Errorf("biscuit: unsupported public key algorithm %q", algorithm)
	}
	key, err := hex.DecodeString(encoded)
	if err != nil {
		return PublicKey{}, fmt.Errorf("biscuit: invalid public key %q: %w", s, err)
	}
	if _, err := crypto.ParseVerifier(alg, key); err != nil {
		return PublicKey{}, fmt.Errorf("biscuit: invalid public key %q: %w", s, err)
	}
	return PublicKey{Algorithm: datalog.Algorithm(alg), Key: key}, nil
}

// TrustingPublicKey is the scope `trusting <key>`.
func TrustingPublicKey(key stdcrypto.PublicKey) (Scope, error) {
	pk, err := PublicKeyFrom(key)
	if err != nil {
		return Scope{}, err
	}
	return Scope{Kind: ScopePublicKey, PublicKey: pk}, nil
}

// publicKeyTable interns the public keys of scopes, the way the symbol table
// interns strings: a block carries the keys it introduces, and a scope refers
// to a key by its index in the table of the token.
type publicKeyTable []datalog.PublicKey

func (t publicKeyTable) index(key datalog.PublicKey) (int64, bool) {
	for i, k := range t {
		if k.Equal(key) {
			return int64(i), true
		}
	}
	return 0, false
}

// insert adds the key when the table does not have it; returns its index.
func (t *publicKeyTable) insert(key datalog.PublicKey) int64 {
	if i, ok := t.index(key); ok {
		return i
	}
	*t = append(*t, key)
	return int64(len(*t) - 1)
}

func (t publicKeyTable) with(keys ...datalog.PublicKey) publicKeyTable {
	res := slices.Clone(t)
	for _, k := range keys {
		res.insert(k)
	}
	return res
}

// scopeKeys lists the public keys of a block's scopes, in order of
// appearance, without duplicates.
func scopeKeys(scopes []datalog.Scope, rules []datalog.Rule, checks []datalog.Check) []datalog.PublicKey {
	var keys publicKeyTable
	add := func(scopes []datalog.Scope) {
		for _, s := range scopes {
			if s.Kind == datalog.ScopePublicKey {
				keys.insert(s.PublicKey)
			}
		}
	}
	add(scopes)
	for _, r := range rules {
		add(r.Scopes)
	}
	for _, c := range checks {
		for _, q := range c.Queries {
			add(q.Scopes)
		}
	}
	return keys
}

func hasScopes(scopes []datalog.Scope, rules []datalog.Rule, checks []datalog.Check) bool {
	if len(scopes) > 0 {
		return true
	}
	for _, r := range rules {
		if len(r.Scopes) > 0 {
			return true
		}
	}
	for _, c := range checks {
		for _, q := range c.Queries {
			if len(q.Scopes) > 0 {
				return true
			}
		}
	}
	return false
}

func tokenScopeToProtoScope(scope datalog.Scope, keys publicKeyTable) (*pb.Scope, error) {
	switch scope.Kind {
	case datalog.ScopeAuthority:
		return &pb.Scope{Content: &pb.Scope_ScopeType_{ScopeType: pb.Scope_Authority}}, nil
	case datalog.ScopePrevious:
		return &pb.Scope{Content: &pb.Scope_ScopeType_{ScopeType: pb.Scope_Previous}}, nil
	case datalog.ScopePublicKey:
		i, ok := keys.index(scope.PublicKey)
		if !ok {
			return nil, fmt.Errorf("biscuit: public key %s is not in the key table", scope.PublicKey)
		}
		return &pb.Scope{Content: &pb.Scope_PublicKey{PublicKey: i}}, nil
	default:
		return nil, fmt.Errorf("biscuit: unsupported scope kind: %d", scope.Kind)
	}
}

func protoScopeToTokenScope(scope *pb.Scope, keys publicKeyTable) (datalog.Scope, error) {
	switch content := scope.GetContent().(type) {
	case *pb.Scope_ScopeType_:
		switch content.ScopeType {
		case pb.Scope_Authority:
			return datalog.Scope{Kind: datalog.ScopeAuthority}, nil
		case pb.Scope_Previous:
			return datalog.Scope{Kind: datalog.ScopePrevious}, nil
		default:
			return datalog.Scope{}, fmt.Errorf("biscuit: unsupported scope type: %s", content.ScopeType)
		}
	case *pb.Scope_PublicKey:
		if content.PublicKey < 0 || content.PublicKey >= int64(len(keys)) {
			return datalog.Scope{}, fmt.Errorf("biscuit: public key index %d out of the key table", content.PublicKey)
		}
		return datalog.Scope{Kind: datalog.ScopePublicKey, PublicKey: keys[content.PublicKey]}, nil
	default:
		return datalog.Scope{}, errors.New("biscuit: empty scope")
	}
}

func tokenScopesToProtoScopes(scopes []datalog.Scope, keys publicKeyTable) ([]*pb.Scope, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	res := make([]*pb.Scope, len(scopes))
	for i, s := range scopes {
		pbScope, err := tokenScopeToProtoScope(s, keys)
		if err != nil {
			return nil, err
		}
		res[i] = pbScope
	}
	return res, nil
}

func protoScopesToTokenScopes(scopes []*pb.Scope, keys publicKeyTable) ([]datalog.Scope, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	res := make([]datalog.Scope, len(scopes))
	for i, s := range scopes {
		scope, err := protoScopeToTokenScope(s, keys)
		if err != nil {
			return nil, err
		}
		res[i] = scope
	}
	return res, nil
}

func tokenPublicKeyToProtoPublicKey(key datalog.PublicKey) *pb.PublicKey {
	return &pb.PublicKey{
		Algorithm: pb.PublicKey_Algorithm(key.Algorithm).Enum(),
		Key:       key.Key,
	}
}

func protoPublicKeyToTokenPublicKey(key *pb.PublicKey) (datalog.PublicKey, error) {
	// ParseVerifier validates the encoding for the algorithm.
	if _, err := crypto.ParseVerifier(key.GetAlgorithm(), key.GetKey()); err != nil {
		return datalog.PublicKey{}, err
	}
	return datalog.PublicKey{Algorithm: datalog.Algorithm(key.GetAlgorithm()), Key: key.GetKey()}, nil
}
