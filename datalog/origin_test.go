// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOrigin(t *testing.T) {
	o := NewOrigin(2, 0, 2)
	require.Equal(t, Origin{0, 2}, o)
	require.Equal(t, Origin{0, 1, 2}, o.With(1))
	require.Equal(t, Origin{0, 2}, o, "With must not modify the receiver")
	require.Equal(t, Origin{0, 2, AuthorizerBlockID}, o.Union(NewOrigin(AuthorizerBlockID)))
	require.Equal(t, "[0, 2]", o.String())
	require.Equal(t, "[authorizer]", NewOrigin(AuthorizerBlockID).String())

	require.True(t, NewOrigin(0).IsSubsetOf(o))
	require.True(t, Origin(nil).IsSubsetOf(o))
	require.False(t, NewOrigin(1).IsSubsetOf(o))

	trusted := DefaultTrustedOrigins().With(1)
	require.True(t, trusted.Contains(NewOrigin(0, 1)))
	require.False(t, trusted.Contains(NewOrigin(1, 2)))
}

// A rule only reads the facts of the origins it trusts, and the facts it
// derives carry the origins of what they were built from plus the rule's
// block.
func TestWorldOrigins(t *testing.T) {
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms}
	user := syms.Insert("user")
	group := syms.Insert("group")
	member := syms.Insert("member")
	alice := syms.Insert("alice")
	admin := syms.Insert("admin")
	u, g := Variable(syms.Insert("u")), Variable(syms.Insert("g"))

	w := NewWorld()
	w.AddFact(NewOrigin(0), Fact{Predicate{user, []Term{alice}}})
	w.AddFact(NewOrigin(1), Fact{Predicate{group, []Term{alice, admin}}})

	// member($u, $g) <- user($u), group($u, $g)
	rule := Rule{
		Head: Predicate{member, []Term{u, g}},
		Body: []Predicate{
			{user, []Term{u}},
			{group, []Term{u, g}},
		},
	}

	// From block 2 with the default scope, block 1 is not visible.
	w.AddRule(2, DefaultTrustedOrigins().With(2), rule)
	require.NoError(t, w.Run(syms))
	require.Equal(t, []OriginFacts{
		{NewOrigin(0), FactSet{{Predicate{user, []Term{alice}}}}},
		{NewOrigin(1), FactSet{{Predicate{group, []Term{alice, admin}}}}},
	}, w.Facts())

	// Trusting block 1 as well, the derived fact comes from blocks 0, 1 and 2.
	w.ResetRules()
	w.AddRule(2, DefaultTrustedOrigins().With(1, 2), rule)
	require.NoError(t, w.Run(syms))
	require.Equal(t, []OriginFacts{
		{NewOrigin(0), FactSet{{Predicate{user, []Term{alice}}}}},
		{NewOrigin(0, 1, 2), FactSet{{Predicate{member, []Term{alice, admin}}}}},
		{NewOrigin(1), FactSet{{Predicate{group, []Term{alice, admin}}}}},
	}, w.Facts())

	// Queries follow the same visibility.
	res, err := w.QueryRule(rule, AuthorizerBlockID, DefaultTrustedOrigins(), syms)
	require.NoError(t, err)
	require.Empty(t, *res)
	res, err = w.QueryRule(rule, AuthorizerBlockID, DefaultTrustedOrigins().With(1), syms)
	require.NoError(t, err)
	require.Len(t, *res, 1)

	require.Len(t, *w.Query(DefaultTrustedOrigins().With(1, 2), Predicate{member, []Term{u, g}}), 1)
	require.Empty(t, *w.Query(DefaultTrustedOrigins().With(1), Predicate{member, []Term{u, g}}))

	require.Equal(t, `// Facts:
// origin: [0]
user("alice");
// origin: [0, 1, 2]
member("alice", "admin");
// origin: [1]
group("alice", "admin");

// Rules:
// origin: 2
member($u, $g) <- user($u), group($u, $g);
`, dbg.World(w))
}

// The same fact stated by two blocks is kept once per origin.
func TestWorldAddFactPerOrigin(t *testing.T) {
	syms := &SymbolTable{}
	f := Fact{Predicate{syms.Insert("f"), nil}}
	w := NewWorld()
	require.True(t, w.AddFact(NewOrigin(0), f))
	require.False(t, w.AddFact(NewOrigin(0), f))
	require.True(t, w.AddFact(NewOrigin(1), f))
	require.Equal(t, 2, w.factCount())
}

// Clone must not share fact storage with the original.
func TestWorldCloneIsIndependent(t *testing.T) {
	syms := &SymbolTable{}
	a := Fact{Predicate{syms.Insert("a"), nil}}
	b := Fact{Predicate{syms.Insert("b"), nil}}
	c := Fact{Predicate{syms.Insert("c"), nil}}

	w := NewWorld()
	w.AddFact(NewOrigin(0), a)
	w1 := w.Clone()
	w2 := w.Clone()
	w1.AddFact(NewOrigin(0), b)
	w2.AddFact(NewOrigin(0), c)

	require.Equal(t, FactSet{a}, w.Facts()[0].Facts)
	require.Equal(t, FactSet{a, b}, w1.Facts()[0].Facts)
	require.Equal(t, FactSet{a, c}, w2.Facts()[0].Facts)
}
