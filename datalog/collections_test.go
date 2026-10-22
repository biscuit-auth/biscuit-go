// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArrayAndMapTerms(t *testing.T) {
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms}
	a, b := syms.Insert("a"), syms.Insert("b")

	arr := Array{Integer(1), Integer(2), a}
	require.True(t, arr.Equal(Array{Integer(1), Integer(2), a}))
	require.False(t, arr.Equal(Array{Integer(2), Integer(1), a}), "arrays are ordered")
	require.False(t, arr.Equal(Set{Integer(1), Integer(2), a}))
	require.True(t, arr.HasPrefix(Array{Integer(1), Integer(2)}))
	require.False(t, arr.HasPrefix(Array{Integer(2)}))
	require.True(t, arr.HasSuffix(Array{a}))
	require.Equal(t, `[1, 2, "a"]`, dbg.Term(arr))

	// Entries are ordered by key, integers first, whatever the insertion order.
	m := NewMap(MapEntry{b, Integer(2)}, MapEntry{Integer(1), a}, MapEntry{a, Integer(1)})
	require.Equal(t, Map{{Integer(1), a}, {a, Integer(1)}, {b, Integer(2)}}, m)
	require.True(t, m.Equal(NewMap(MapEntry{a, Integer(1)}, MapEntry{b, Integer(2)}, MapEntry{Integer(1), a})))
	require.False(t, m.Equal(NewMap(MapEntry{a, Integer(1)})))
	require.Equal(t, Integer(2), m.Get(b))
	require.Nil(t, m.Get(Integer(2)))
	require.Equal(t, `{1: "a", "a": 1, "b": 2}`, dbg.Term(m))
	require.Equal(t, Integer(3), NewMap(MapEntry{a, Integer(1)}, MapEntry{a, Integer(3)}).Get(a), "a repeated key keeps the last value")
	require.Equal(t, "{}", dbg.Term(Map{}))
}

func TestArrayAndMapOperators(t *testing.T) {
	syms := &SymbolTable{}
	a, b, c := syms.Insert("a"), syms.Insert("b"), syms.Insert("c")
	kv := Variable(syms.Insert("kv"))
	arr := Array{a, b}
	m := NewMap(MapEntry{Integer(1), syms.Insert("A")}, MapEntry{a, Integer(1)}, MapEntry{b, Integer(2)})

	for _, tc := range []struct {
		expr    Expression
		want    Term
		printed string
	}{
		{Expression{Value{Array{Integer(1), Integer(2), Integer(1)}}, UnaryOp{Length{}}}, Integer(3), "[1, 2, 1].length()"},
		{Expression{Value{m}, UnaryOp{Length{}}}, Integer(3), `{1: "A", "a": 1, "b": 2}.length()`},
		{Expression{Value{arr}, Value{Bool(true)}, BinaryOp{HeterogeneousNotEqual{}}}, Bool(true), `["a", "b"] != true`},
		{Expression{Value{arr}, Value{Array{a, b}}, BinaryOp{Equal{}}}, Bool(true), `["a", "b"] === ["a", "b"]`},
		{Expression{Value{arr}, Value{Array{a, c}}, BinaryOp{NotEqual{}}}, Bool(true), `["a", "b"] !== ["a", "c"]`},
		{Expression{Value{Array{a, b, c}}, Value{c}, BinaryOp{Contains{}}}, Bool(true), `["a", "b", "c"].contains("c")`},
		{Expression{Value{Array{Integer(1), Integer(2), Integer(3)}}, Value{Array{Integer(1), Integer(2)}}, BinaryOp{Prefix{}}}, Bool(true), "[1, 2, 3].starts_with([1, 2])"},
		{Expression{Value{Array{Integer(4), Integer(5), Integer(6)}}, Value{Array{Integer(6)}}, BinaryOp{Suffix{}}}, Bool(true), "[4, 5, 6].ends_with([6])"},
		{Expression{Value{Array{Integer(1), Integer(2), a}}, Value{Integer(2)}, BinaryOp{Get{}}}, a, `[1, 2, "a"].get(2)`},
		{Expression{Value{Array{Integer(1), Integer(2)}}, Value{Integer(3)}, BinaryOp{Get{}}}, Null{}, "[1, 2].get(3)"},
		{Expression{Value{m}, Value{b}, BinaryOp{Contains{}}}, Bool(true), `{1: "A", "a": 1, "b": 2}.contains("b")`},
		{Expression{Value{m}, Value{Integer(2)}, BinaryOp{Contains{}}}, Bool(false), `{1: "A", "a": 1, "b": 2}.contains(2)`},
		{Expression{Value{m}, Value{a}, BinaryOp{Get{}}}, Integer(1), `{1: "A", "a": 1, "b": 2}.get("a")`},
		{Expression{Value{m}, Value{Integer(1)}, BinaryOp{Get{}}}, syms.Insert("A"), `{1: "A", "a": 1, "b": 2}.get(1)`},
		{Expression{Value{m}, Value{c}, BinaryOp{Get{}}}, Null{}, `{1: "A", "a": 1, "b": 2}.get("c")`},
		{Expression{Value{m}, Value{m}, BinaryOp{HeterogeneousEqual{}}}, Bool(true), `{1: "A", "a": 1, "b": 2} == {1: "A", "a": 1, "b": 2}`},
		{Expression{Value{m}, Value{NewMap(MapEntry{a, Integer(1)})}, BinaryOp{NotEqual{}}}, Bool(true), `{1: "A", "a": 1, "b": 2} !== {"a": 1}`},
		// .all() and .any() over an array, and over a map as [key, value] pairs.
		{Expression{Value{Array{Integer(1), Integer(2), Integer(3)}}, Closure{[]Variable{kv}, Expression{Value{kv}, Value{Integer(0)}, BinaryOp{GreaterThan{}}}}, BinaryOp{All{}}}, Bool(true), "[1, 2, 3].all($kv -> $kv > 0)"},
		{Expression{Value{m}, Closure{[]Variable{kv}, Expression{
			Value{kv}, Value{Integer(0)}, BinaryOp{Get{}}, Value{Integer(1)}, BinaryOp{HeterogeneousEqual{}},
			Closure{nil, Expression{Value{kv}, Value{Integer(1)}, BinaryOp{Get{}}, Value{syms.Insert("A")}, BinaryOp{HeterogeneousEqual{}}}},
			BinaryOp{LazyAnd{}},
		}}, BinaryOp{Any{}}}, Bool(true), `{1: "A", "a": 1, "b": 2}.any($kv -> $kv.get(0) == 1 && $kv.get(1) == "A")`},
		// Nested maps and arrays.
		{Expression{
			Value{NewMap(MapEntry{syms.Insert("user"), NewMap(MapEntry{syms.Insert("id"), Integer(1)}, MapEntry{syms.Insert("roles"), Array{syms.Insert("admin")}})})},
			Value{syms.Insert("user")}, BinaryOp{Get{}},
			Value{syms.Insert("roles")}, BinaryOp{Get{}},
			Value{syms.Insert("admin")}, BinaryOp{Contains{}},
		}, Bool(true), `{"user": {"id": 1, "roles": ["admin"]}}.get("user").get("roles").contains("admin")`},
	} {
		t.Run(tc.printed, func(t *testing.T) {
			res, err := tc.expr.Evaluate(nil, syms)
			require.NoError(t, err)
			require.Equal(t, tc.want, res)
			require.Equal(t, tc.printed, tc.expr.Print(syms))
		})
	}

	bad := Expression{Value{arr}, Value{a}, BinaryOp{Get{}}}
	_, err := bad.Evaluate(nil, syms)
	require.Error(t, err, "an array index must be an integer")
	bad = Expression{Value{m}, Value{Bool(true)}, BinaryOp{Get{}}}
	_, err = bad.Evaluate(nil, syms)
	require.Error(t, err, "a map key must be an integer or a string")
}
