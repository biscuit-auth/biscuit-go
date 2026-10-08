// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
)

// BlockID identifies the source of a fact or rule: the authority block is 0,
// the following blocks count up, and the authorizer is AuthorizerBlockID.
type BlockID uint64

const AuthorizerBlockID BlockID = math.MaxUint64

func (b BlockID) String() string {
	if b == AuthorizerBlockID {
		return "authorizer"
	}
	return strconv.FormatUint(uint64(b), 10)
}

// Origin is the set of blocks a fact derives from: the block that stated it,
// or for a derived fact the blocks of every fact the rule matched plus the
// block of the rule. It is sorted and has no duplicates.
type Origin []BlockID

func NewOrigin(ids ...BlockID) Origin {
	return Origin(nil).With(ids...)
}

// With returns a copy of the origin extended with the given blocks.
func (o Origin) With(ids ...BlockID) Origin {
	res := make(Origin, 0, len(o)+len(ids))
	res = append(res, o...)
	res = append(res, ids...)
	slices.Sort(res)
	return slices.Compact(res)
}

func (o Origin) Union(other Origin) Origin {
	return o.With(other...)
}

func (o Origin) Equal(other Origin) bool {
	return slices.Equal(o, other)
}

// IsSubsetOf reports whether every block of o is in other.
func (o Origin) IsSubsetOf(other Origin) bool {
	for _, id := range o {
		if _, found := slices.BinarySearch(other, id); !found {
			return false
		}
	}
	return true
}

// Compare orders origins by their block ids; the authorizer sorts last.
func (o Origin) Compare(other Origin) int {
	return slices.Compare(o, other)
}

func (o Origin) String() string {
	ids := make([]string, len(o))
	for i, id := range o {
		ids[i] = id.String()
	}
	return fmt.Sprintf("[%s]", strings.Join(ids, ", "))
}

// TrustedOrigins is the set of blocks a rule, check or policy may read facts
// from. A fact is visible when its whole origin is trusted.
type TrustedOrigins Origin

// DefaultTrustedOrigins is what a rule trusts without an explicit scope: the
// authority block and the authorizer. The rule's own block is added by the
// caller.
func DefaultTrustedOrigins() TrustedOrigins {
	return TrustedOrigins(NewOrigin(0, AuthorizerBlockID))
}

func NewTrustedOrigins(ids ...BlockID) TrustedOrigins {
	return TrustedOrigins(NewOrigin(ids...))
}

func (t TrustedOrigins) With(ids ...BlockID) TrustedOrigins {
	return TrustedOrigins(Origin(t).With(ids...))
}

func (t TrustedOrigins) Contains(o Origin) bool {
	return o.IsSubsetOf(Origin(t))
}

func (t TrustedOrigins) Equal(other TrustedOrigins) bool {
	return Origin(t).Equal(Origin(other))
}

func (t TrustedOrigins) String() string {
	return Origin(t).String()
}
