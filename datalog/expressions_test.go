// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func idptr(v Term) *Term {
	return &v
}

func TestUnaryNegate(t *testing.T) {
	ops := Expression{
		Value{Bool(true)},
		UnaryOp{Negate{}},
		UnaryOp{Negate{}},
	}

	syms := &SymbolTable{}
	res, err := ops.Evaluate(nil, syms)
	require.NoError(t, err)
	require.Equal(t, Bool(true), res)
}

func TestUnaryParens(t *testing.T) {
	ops := Expression{
		Value{Integer(1)},
		Value{Variable(2)},
		Value{Integer(3)},
		BinaryOp{Mul{}},
		BinaryOp{Add{}},
	}

	values := map[Variable]*Term{
		2: idptr(Integer(2)),
	}

	syms := &SymbolTable{}
	res, err := ops.Evaluate(values, syms)
	require.NoError(t, err)
	require.Equal(t, Integer(7), res)

	ops = Expression{
		Value{Integer(1)},
		Value{Variable(2)},
		BinaryOp{Add{}},
		UnaryOp{Parens{}},
		Value{Integer(3)},
		BinaryOp{Mul{}},
	}

	res, err = ops.Evaluate(values, syms)
	require.NoError(t, err)
	require.Equal(t, Integer(9), res)
}

func TestBinaryLessThan(t *testing.T) {
	require.Equal(t, BinaryLessThan, LessThan{}.Type())
	syms := &SymbolTable{}

	testCases := []struct {
		desc        string
		left        Term
		right       Term
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "not less than",
			left:  Integer(5),
			right: Integer(3),
			res:   false,
		},
		{
			desc:  "not less than negative",
			left:  Integer(0),
			right: Integer(-7),
			res:   false,
		},
		{
			desc:  "less than",
			left:  Integer(3),
			right: Integer(7),
			res:   true,
		},
		{
			desc:  "less than negative",
			left:  Integer(-10),
			right: Integer(-3),
			res:   true,
		},
		{
			desc:  "equal check",
			left:  Integer(42),
			right: Integer(42),
			res:   false,
		},
		{
			desc:        "invalid left type errors",
			left:        String(42),
			right:       Integer(42),
			expectedErr: true,
		},
		{
			desc:        "invalid right type errors",
			left:        Integer(42),
			right:       syms.Insert("abc"),
			expectedErr: true,
		},
		{
			desc:        "invalid both type errors",
			left:        syms.Insert("def"),
			right:       syms.Insert("abc"),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{LessThan{}},
			}

			res, err := ops.Evaluate(nil, syms)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryLessOrEqual(t *testing.T) {
	require.Equal(t, BinaryLessOrEqual, LessOrEqual{}.Type())
	syms := &SymbolTable{}

	testCases := []struct {
		desc        string
		left        Term
		right       Term
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "not less or equal integers",
			left:  Integer(5),
			right: Integer(3),
			res:   false,
		},
		{
			desc:  "not less or equal dates",
			left:  Date(5),
			right: Date(3),
			res:   false,
		},
		{
			desc:  "not less or equal negative integers",
			left:  Integer(0),
			right: Integer(-7),
			res:   false,
		},
		{
			desc:  "less integers",
			left:  Integer(3),
			right: Integer(7),
			res:   true,
		},
		{
			desc:  "less dates",
			left:  Date(0),
			right: Date(3),
			res:   true,
		},
		{
			desc:  "less negative integers",
			left:  Integer(-10),
			right: Integer(-3),
			res:   true,
		},
		{
			desc:  "equal checks integers",
			left:  Integer(42),
			right: Integer(42),
			res:   true,
		},
		{
			desc:  "equal checks dates",
			left:  Date(3),
			right: Date(3),
			res:   true,
		},
		{
			desc:  "equal checks negative integers",
			left:  Integer(-1),
			right: Integer(-1),
			res:   true,
		},
		{
			desc:        "invalid left type errors",
			left:        String(42),
			right:       Integer(42),
			expectedErr: true,
		},
		{
			desc:        "invalid right type errors",
			left:        Integer(42),
			right:       syms.Insert("abc"),
			expectedErr: true,
		},
		{
			desc:        "invalid both type errors",
			left:        syms.Insert("def"),
			right:       syms.Insert("abc"),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{LessOrEqual{}},
			}

			res, err := ops.Evaluate(nil, syms)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryGreaterThan(t *testing.T) {
	require.Equal(t, BinaryGreaterThan, GreaterThan{}.Type())
	syms := &SymbolTable{}

	testCases := []struct {
		desc        string
		left        Term
		right       Term
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "not greater than",
			left:  Integer(3),
			right: Integer(5),
			res:   false,
		},
		{
			desc:  "not greater than negative",
			left:  Integer(-7),
			right: Integer(0),
			res:   false,
		},
		{
			desc:  "greater than",
			left:  Integer(7),
			right: Integer(3),
			res:   true,
		},
		{
			desc:  "greater than negative",
			left:  Integer(-3),
			right: Integer(-10),
			res:   true,
		},
		{
			desc:  "equal check",
			left:  Integer(42),
			right: Integer(42),
			res:   false,
		},
		{
			desc:        "invalid left type errors",
			left:        String(42),
			right:       Integer(42),
			expectedErr: true,
		},
		{
			desc:        "invalid right type errors",
			left:        Integer(42),
			right:       syms.Insert("abc"),
			expectedErr: true,
		},
		{
			desc:        "invalid both type errors",
			left:        syms.Insert("def"),
			right:       syms.Insert("abc"),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{GreaterThan{}},
			}

			res, err := ops.Evaluate(nil, syms)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryGreaterOrEqual(t *testing.T) {
	require.Equal(t, BinaryGreaterOrEqual, GreaterOrEqual{}.Type())

	syms := &SymbolTable{}
	testCases := []struct {
		desc        string
		left        Term
		right       Term
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "not greater or equal integers",
			left:  Integer(3),
			right: Integer(5),
			res:   false,
		},
		{
			desc:  "not greater or equal dates",
			left:  Date(3),
			right: Date(5),
			res:   false,
		},
		{
			desc:  "not greater or equal negative integers",
			left:  Integer(-7),
			right: Integer(0),
			res:   false,
		},
		{
			desc:  "greater integers",
			left:  Integer(7),
			right: Integer(3),
			res:   true,
		},
		{
			desc:  "greater dates",
			left:  Date(3),
			right: Date(0),
			res:   true,
		},
		{
			desc:  "greater negative integers",
			left:  Integer(-3),
			right: Integer(-10),
			res:   true,
		},
		{
			desc:  "equal checks integers",
			left:  Integer(42),
			right: Integer(42),
			res:   true,
		},
		{
			desc:  "equal checks dates",
			left:  Date(3),
			right: Date(3),
			res:   true,
		},
		{
			desc:  "equal checks negative integers",
			left:  Integer(-1),
			right: Integer(-1),
			res:   true,
		},
		{
			desc:        "invalid left type errors",
			left:        String(42),
			right:       Integer(42),
			expectedErr: true,
		},
		{
			desc:        "invalid right type errors",
			left:        Integer(42),
			right:       syms.Insert("abc"),
			expectedErr: true,
		},
		{
			desc:        "invalid both type errors",
			left:        syms.Insert("def"),
			right:       syms.Insert("abc"),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{GreaterOrEqual{}},
			}

			res, err := ops.Evaluate(nil, syms)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryNotEqual(t *testing.T) {
	require.Equal(t, BinaryNotEqual, NotEqual{}.Type())
	syms := &SymbolTable{}

	for _, tc := range []struct {
		desc        string
		left, right Term
		res         Bool
		expectedErr bool
	}{
		{desc: "different integers", left: Integer(1), right: Integer(3), res: true},
		{desc: "same integers", left: Integer(3), right: Integer(3), res: false},
		{desc: "different strings", left: syms.Insert("abcD12x"), right: syms.Insert("abcD12"), res: true},
		{desc: "different bytes", left: Bytes{0x12, 0xab, 0xcd}, right: Bytes{0x12, 0xab}, res: true},
		{desc: "different dates", left: Date(2), right: Date(1), res: true},
		{desc: "different bools", left: Bool(true), right: Bool(false), res: true},
		{desc: "different sets", left: Set{Integer(1), Integer(4)}, right: Set{Integer(1), Integer(2)}, res: true},
		{desc: "same sets", left: Set{Integer(1), Integer(2)}, right: Set{Integer(2), Integer(1)}, res: false},
		{desc: "type mismatch errors", left: Integer(1), right: syms.Insert("1"), expectedErr: true},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			expr := Expression{Value{tc.left}, Value{tc.right}, BinaryOp{NotEqual{}}}
			res, err := expr.Evaluate(nil, syms)
			if tc.expectedErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.res, res)
		})
	}
}

// == and != compare across types since datalog v3.3: different types are
// not equal, where === and !== are a type error.
func TestBinaryHeterogeneousEqual(t *testing.T) {
	syms := &SymbolTable{}
	require.Equal(t, BinaryHeterogeneousEqual, HeterogeneousEqual{}.Type())
	require.Equal(t, BinaryHeterogeneousNotEqual, HeterogeneousNotEqual{}.Type())

	for _, tc := range []struct {
		left, right Term
		equal       bool
	}{
		{Integer(1), Integer(1), true},
		{Integer(1), Integer(3), false},
		{Integer(1), Bool(true), false},
		{syms.Insert("abcD12x"), Bool(true), false},
		{Bytes{0x12}, Bytes{0x12}, true},
		{Set{Integer(1), Integer(4)}, Set{Integer(1), Integer(2)}, false},
		{Set{Integer(1), Integer(4)}, Bool(true), false},
	} {
		eq := Expression{Value{tc.left}, Value{tc.right}, BinaryOp{HeterogeneousEqual{}}}
		res, err := eq.Evaluate(nil, syms)
		require.NoError(t, err)
		require.Equal(t, Bool(tc.equal), res, "%v == %v", tc.left, tc.right)

		ne := Expression{Value{tc.left}, Value{tc.right}, BinaryOp{HeterogeneousNotEqual{}}}
		res, err = ne.Evaluate(nil, syms)
		require.NoError(t, err)
		require.Equal(t, Bool(!tc.equal), res, "%v != %v", tc.left, tc.right)
	}

	strict := Expression{Value{Integer(1)}, Value{Bool(true)}, BinaryOp{Equal{}}}
	_, err := strict.Evaluate(nil, syms)
	require.Error(t, err)

	printed := Expression{Value{Integer(1)}, Value{Bool(true)}, BinaryOp{HeterogeneousNotEqual{}}}
	require.Equal(t, "1 != true", printed.Print(syms))
}

func TestBinaryBitwise(t *testing.T) {
	syms := &SymbolTable{}
	for _, tc := range []struct {
		op          BinaryOpFunc
		opType      BinaryOpType
		left, right Term
		res         Integer
		printed     string
	}{
		{BitwiseAnd{}, BinaryBitwiseAnd, Integer(6), Integer(3), 2, "6 & 3"},
		{BitwiseOr{}, BinaryBitwiseOr, Integer(1), Integer(2), 3, "1 | 2"},
		{BitwiseXor{}, BinaryBitwiseXor, Integer(3), Integer(3), 0, "3 ^ 3"},
		{BitwiseAnd{}, BinaryBitwiseAnd, Integer(-1), Integer(255), 255, "-1 & 255"},
	} {
		t.Run(tc.printed, func(t *testing.T) {
			require.Equal(t, tc.opType, tc.op.Type())
			expr := Expression{Value{tc.left}, Value{tc.right}, BinaryOp{tc.op}}
			res, err := expr.Evaluate(nil, syms)
			require.NoError(t, err)
			require.Equal(t, tc.res, res)
			require.Equal(t, tc.printed, expr.Print(syms))

			mismatch := Expression{Value{tc.left}, Value{Bool(true)}, BinaryOp{tc.op}}
			_, err = mismatch.Evaluate(nil, syms)
			require.Error(t, err)
		})
	}
}

func TestBinaryEqual(t *testing.T) {
	require.Equal(t, BinaryEqual, Equal{}.Type())
	syms := &SymbolTable{}

	testCases := []struct {
		desc        string
		left        Term
		right       Term
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "not equal integers",
			left:  Integer(3),
			right: Integer(5),
			res:   false,
		},
		{
			desc:  "not equal bytes",
			left:  Bytes{0},
			right: Bytes{1},
			res:   false,
		},
		{
			desc:  "not equal string",
			left:  syms.Insert("abc"),
			right: syms.Insert("def"),
			res:   false,
		},
		{
			desc:  "equal integers",
			left:  Integer(3),
			right: Integer(3),
			res:   true,
		},
		{
			desc:  "equal bytes",
			left:  Bytes{0, 1, 2},
			right: Bytes{0, 1, 2},
			res:   true,
		},
		{
			desc:  "equal strings",
			left:  syms.Insert("abc"),
			right: syms.Insert("abc"),
			res:   true,
		},
		{
			desc:        "invalid left type errors",
			left:        String(42),
			right:       Integer(42),
			expectedErr: true,
		},
		{
			desc:        "invalid right type errors",
			left:        Integer(42),
			right:       syms.Insert("abc"),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Equal{}},
			}

			res, err := ops.Evaluate(nil, syms)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryContains(t *testing.T) {
	require.Equal(t, BinaryContains, Contains{}.Type())
	syms := &SymbolTable{}

	tests := []struct {
		name    string
		left    Term
		right   Term
		want    Term
		wantErr bool
	}{
		{
			name:  "integer in set",
			left:  Set{Integer(1), Integer(2), Integer(3)},
			right: Integer(1),
			want:  Bool(true),
		},
		{
			name:  "string not in set",
			left:  Set{syms.Insert("def"), syms.Insert("ijk")},
			right: syms.Insert("abc"),
			want:  Bool(false),
		},
		{
			name:  "bytes in set",
			left:  Set{Bytes("abc"), Bytes("def")},
			right: Bytes("abc"),
			want:  Bool(true),
		},
		{
			name:  "symbol not in set",
			left:  Set{String(1), String(2)},
			right: String(0),
			want:  Bool(false),
		},
		{
			name:  "set element type mismatch",
			left:  Set{Integer(1), Integer(2)},
			right: String(0),
			want:  Bool(false),
		},
		{
			name:  "bool in set",
			left:  Set{Bool(true), Bool(false)},
			right: Bool(true),
			want:  Bool(true),
		},
		{
			name:  "date not in set",
			left:  Set{Date(1), Date(2)},
			right: Date(0),
			want:  Bool(false),
		},
		{
			name:  "set not subset",
			left:  Set{Integer(1), Integer(2)},
			right: Set{Integer(0)},
			want:  Bool(false),
		},
		{
			name:  "set is subset",
			left:  Set{Integer(1), Integer(2)},
			right: Set{Integer(1)},
			want:  Bool(true),
		},
		{
			name:    "variable in set",
			left:    Set{Integer(1), Integer(2)},
			right:   Variable(0),
			wantErr: true,
		},
		{
			name:    "invalid left type not a set",
			left:    Integer(0),
			right:   Integer(0),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Contains{}.Eval(tt.left, tt.right, syms)
			require.Equal(t, tt.wantErr, (err != nil))
			require.Equal(t, tt.want, got)
		})
	}
}

func TestBinaryPrefix(t *testing.T) {
	require.Equal(t, BinaryPrefix, Prefix{}.Type())
	syms := &SymbolTable{}

	testCases := []struct {
		desc        string
		left        Term
		right       Term
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "prefix",
			left:  syms.Insert("abcdef"),
			right: syms.Insert("abc"),
			res:   true,
		},
		{
			desc:  "not prefix",
			left:  syms.Insert("abcdef"),
			right: syms.Insert("def"),
			res:   false,
		},
		{
			desc:  "not prefix 2",
			left:  syms.Insert("abc"),
			right: syms.Insert("abcdef"),
			res:   false,
		},
		{
			desc:        "invalid right type errors",
			left:        syms.Insert("abc"),
			right:       Integer(42),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Prefix{}},
			}

			res, err := ops.Evaluate(nil, syms)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinarySuffix(t *testing.T) {
	require.Equal(t, BinarySuffix, Suffix{}.Type())
	syms := &SymbolTable{}

	testCases := []struct {
		desc        string
		left        Term
		right       Term
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "suffix",
			left:  syms.Insert("abcdef"),
			right: syms.Insert("def"),
			res:   true,
		},
		{
			desc:  "not suffix",
			left:  syms.Insert("abcdef"),
			right: syms.Insert("abc"),
			res:   false,
		},
		{
			desc:  "not suffix 2",
			left:  syms.Insert("def"),
			right: syms.Insert("abcdef"),
			res:   false,
		},
		{
			desc:        "invalid right type errors",
			left:        syms.Insert("abc"),
			right:       Integer(42),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Suffix{}},
			}

			res, err := ops.Evaluate(nil, syms)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryRegex(t *testing.T) {
	require.Equal(t, BinaryRegex, Regex{}.Type())
	syms := &SymbolTable{}

	testCases := []struct {
		desc        string
		left        Term
		right       Term
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "regex match",
			left:  syms.Insert("abcdef"),
			right: syms.Insert("def$"),
			res:   true,
		},
		{
			desc:  "regex match 2",
			left:  syms.Insert("abcdef"),
			right: syms.Insert("[a-f]{6}"),
			res:   true,
		},
		{
			desc:  "regex no match",
			left:  syms.Insert("abc"),
			right: syms.Insert("ABC"),
			res:   false,
		},
		{
			desc:        "invalid right type errors",
			left:        syms.Insert("abc"),
			right:       Integer(42),
			expectedErr: true,
		},
		{
			desc:        "invalid regexp",
			left:        syms.Insert("abc"),
			right:       syms.Insert("[abc"),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Regex{}},
			}

			res, err := ops.Evaluate(nil, syms)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryAdd(t *testing.T) {
	require.Equal(t, BinaryAdd, Add{}.Type())
	syms := &SymbolTable{}

	testCases := []struct {
		desc            string
		left            Term
		right           Term
		res             Term
		expectedErr     bool
		expectedErrType error
	}{
		{
			desc:  "normal addition",
			left:  Integer(5),
			right: Integer(3),
			res:   Integer(8),
		},
		{
			desc:  "addition with negative numbers",
			left:  Integer(10),
			right: Integer(-7),
			res:   Integer(3),
		},
		{
			desc:  "addition with negative numbers 2",
			left:  Integer(-7),
			right: Integer(-3),
			res:   Integer(-10),
		},
		{
			desc:        "invalid left type",
			left:        syms.Insert("abc"),
			right:       Integer(-3),
			expectedErr: true,
		},
		{
			desc:        "invalid right type",
			left:        Integer(-3),
			right:       syms.Insert("abc"),
			expectedErr: true,
		},
		{
			desc:            "handle overflow errors",
			left:            Integer(math.MaxInt64),
			right:           Integer(1),
			expectedErr:     true,
			expectedErrType: ErrInt64Overflow,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Add{}},
			}

			res, err := ops.Evaluate(nil, syms)
			if tc.expectedErr {
				if tc.expectedErrType != nil {
					require.Equal(t, tc.expectedErrType, errors.Unwrap(err))
				} else {
					require.Error(t, err)
				}
			} else {
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinarySub(t *testing.T) {
	require.Equal(t, BinarySub, Sub{}.Type())
	syms := &SymbolTable{}

	testCases := []struct {
		desc            string
		left            Term
		right           Term
		res             Term
		expectedErr     bool
		expectedErrType error
	}{
		{
			desc:  "normal substraction",
			left:  Integer(5),
			right: Integer(3),
			res:   Integer(2),
		},
		{
			desc:  "substraction with negative numbers",
			left:  Integer(10),
			right: Integer(-7),
			res:   Integer(17),
		},
		{
			desc:  "substraction with negative numbers 2",
			left:  Integer(-7),
			right: Integer(-3),
			res:   Integer(-4),
		},
		{
			desc:        "invalid left type",
			left:        syms.Insert("abc"),
			right:       Integer(-3),
			expectedErr: true,
		},
		{
			desc:        "invalid right type",
			left:        Integer(-3),
			right:       syms.Insert("abc"),
			expectedErr: true,
		},
		{
			desc:            "handle overflow errors",
			left:            Integer(math.MinInt64),
			right:           Integer(1),
			expectedErr:     true,
			expectedErrType: ErrInt64Overflow,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Sub{}},
			}

			res, err := ops.Evaluate(nil, syms)
			if tc.expectedErr {
				if tc.expectedErrType != nil {
					require.Equal(t, tc.expectedErrType, errors.Unwrap(err))
				} else {
					require.Error(t, err)
				}
			} else {
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryMul(t *testing.T) {
	require.Equal(t, BinaryMul, Mul{}.Type())
	syms := &SymbolTable{}

	testCases := []struct {
		desc            string
		left            Term
		right           Term
		res             Term
		expectedErr     bool
		expectedErrType error
	}{
		{
			desc:  "normal multiplication",
			left:  Integer(5),
			right: Integer(3),
			res:   Integer(15),
		},
		{
			desc:  "multiplication with negative numbers",
			left:  Integer(10),
			right: Integer(-7),
			res:   Integer(-70),
		},
		{
			desc:  "multiplication with negative numbers 2",
			left:  Integer(-7),
			right: Integer(-3),
			res:   Integer(21),
		},
		{
			desc:        "invalid left type",
			left:        syms.Insert("abc"),
			right:       Integer(-3),
			expectedErr: true,
		},
		{
			desc:        "invalid right type",
			left:        Integer(-3),
			right:       syms.Insert("abc"),
			expectedErr: true,
		},
		{
			desc:            "handle overflow errors",
			left:            Integer(math.MaxInt64),
			right:           Integer(math.MaxInt64),
			expectedErr:     true,
			expectedErrType: ErrInt64Overflow,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Mul{}},
			}

			res, err := ops.Evaluate(nil, syms)
			if tc.expectedErr {
				if tc.expectedErrType != nil {
					require.Equal(t, tc.expectedErrType, errors.Unwrap(err))
				} else {
					require.Error(t, err)
				}
			} else {
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryDiv(t *testing.T) {
	require.Equal(t, BinaryDiv, Div{}.Type())
	syms := &SymbolTable{}

	testCases := []struct {
		desc            string
		left            Term
		right           Term
		res             Term
		expectedErr     bool
		expectedErrType error
	}{
		{
			desc:  "euclidian division",
			left:  Integer(32),
			right: Integer(4),
			res:   Integer(8),
		},
		{
			desc:  "euclidian division with reminder",
			left:  Integer(33),
			right: Integer(4),
			res:   Integer(8),
		},
		{
			desc:        "invalid left type",
			left:        syms.Insert("abc"),
			right:       Integer(-3),
			expectedErr: true,
		},
		{
			desc:        "invalid right type",
			left:        Integer(-3),
			right:       syms.Insert("abc"),
			expectedErr: true,
		},
		{
			desc:            "division by zero",
			left:            Integer(32),
			right:           Integer(0),
			expectedErr:     true,
			expectedErrType: ErrExprDivByZero,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Div{}},
			}

			res, err := ops.Evaluate(nil, syms)
			if tc.expectedErr {
				if tc.expectedErrType != nil {
					require.Equal(t, tc.expectedErrType, errors.Unwrap(err))
				} else {
					require.Error(t, err)
				}
			} else {
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryAnd(t *testing.T) {
	require.Equal(t, BinaryAnd, And{}.Type())
	syms := &SymbolTable{}

	testCases := []struct {
		desc        string
		left        Term
		right       Term
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "and 1",
			left:  Bool(true),
			right: Bool(true),
			res:   true,
		},
		{
			desc:  "and 2",
			left:  Bool(true),
			right: Bool(false),
			res:   false,
		},
		{
			desc:  "and 3",
			left:  Bool(false),
			right: Bool(true),
			res:   false,
		},
		{
			desc:  "and 4",
			left:  Bool(false),
			right: Bool(false),
			res:   false,
		},
		{
			desc:        "invalid left type",
			left:        Integer(0),
			right:       Bool(true),
			expectedErr: true,
		},
		{
			desc:        "invalid right type",
			left:        Bool(true),
			right:       syms.Insert("abc"),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{And{}},
			}

			res, err := ops.Evaluate(nil, syms)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestBinaryOr(t *testing.T) {
	require.Equal(t, BinaryOr, Or{}.Type())
	syms := &SymbolTable{}

	testCases := []struct {
		desc        string
		left        Term
		right       Term
		res         Bool
		expectedErr bool
	}{
		{
			desc:  "or 1",
			left:  Bool(true),
			right: Bool(true),
			res:   true,
		},
		{
			desc:  "or 2",
			left:  Bool(true),
			right: Bool(false),
			res:   true,
		},
		{
			desc:  "or 3",
			left:  Bool(false),
			right: Bool(true),
			res:   true,
		},
		{
			desc:  "or 4",
			left:  Bool(false),
			right: Bool(false),
			res:   false,
		},
		{
			desc:        "invalid left type",
			left:        Integer(0),
			right:       Bool(true),
			expectedErr: true,
		},
		{
			desc:        "invalid right type",
			left:        Bool(true),
			right:       syms.Insert("abc"),
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{tc.left},
				Value{tc.right},
				BinaryOp{Or{}},
			}

			res, err := ops.Evaluate(nil, syms)
			if tc.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.res, res)
			}
		})
	}
}

func TestPrint(t *testing.T) {
	syms := SymbolTable{}
	syms.Insert("abc")
	testCases := []struct {
		desc string
		expr Expression
		res  string
	}{
		{
			desc: "number",
			expr: Expression{Value{Integer(9)}},
			res:  "9",
		},
		{
			desc: "string",
			expr: Expression{Value{syms.Sym("abc")}},
			res:  "\"abc\"",
		},
		{
			desc: "unary",
			expr: Expression{Value{syms.Sym("abc")}, UnaryOp{Length{}}},
			res:  "\"abc\".length()",
		},
		{
			desc: "binary",
			expr: Expression{Value{Integer(9)}, Value{Integer(4)}, BinaryOp{Mul{}}},
			res:  "9 * 4",
		},
		{
			desc: "parens",
			expr: Expression{
				Value{Integer(9)},
				Value{Integer(3)},
				BinaryOp{Add{}},
				UnaryOp{Parens{}},
				Value{Integer(4)},
				BinaryOp{Div{}},
			},
			res: "(9 + 3) / 4",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			p := tc.expr.Print(&syms)
			require.Equal(t, tc.res, p)
		})
	}
}

// Closures: the right side of && and || is evaluated only when needed, and
// .all() / .any() bind their parameter to each element of a set.
func TestClosures(t *testing.T) {
	syms := &SymbolTable{}
	p := Variable(syms.Insert("p"))
	q := Variable(syms.Insert("q"))
	// A closure body that errors, to observe laziness.
	errorBody := Expression{Value{syms.Insert("x")}, Value{syms.Insert("x")}, BinaryOp{Intersection{}}}
	closure := func(params []Variable, body Expression) Closure { return Closure{Params: params, Body: body} }

	for _, tc := range []struct {
		desc    string
		expr    Expression
		want    Term
		printed string
	}{
		{"and short-circuits", Expression{Value{Bool(false)}, closure(nil, errorBody), BinaryOp{LazyAnd{}}}, Bool(false), `false && "x".intersection("x")`},
		{"and evaluates", Expression{Value{Bool(true)}, closure(nil, Expression{Value{Bool(true)}}), BinaryOp{LazyAnd{}}}, Bool(true), "true && true"},
		{"or short-circuits", Expression{Value{Bool(true)}, closure(nil, errorBody), BinaryOp{LazyOr{}}}, Bool(true), `true || "x".intersection("x")`},
		{"or evaluates", Expression{Value{Bool(false)}, closure(nil, Expression{Value{Bool(true)}}), BinaryOp{LazyOr{}}}, Bool(true), "false || true"},
		{"all true", Expression{Value{Set{Integer(1), Integer(2), Integer(3)}}, closure([]Variable{p}, Expression{Value{p}, Value{Integer(0)}, BinaryOp{GreaterThan{}}}), BinaryOp{All{}}}, Bool(true), "{1, 2, 3}.all($p -> $p > 0)"},
		{"all false", Expression{Value{Set{Integer(1), Integer(2), Integer(3)}}, closure([]Variable{p}, Expression{Value{p}, Value{Integer(2)}, BinaryOp{HeterogeneousEqual{}}}), BinaryOp{All{}}}, Bool(false), "{1, 2, 3}.all($p -> $p == 2)"},
		{"any true", Expression{Value{Set{Integer(1), Integer(2), Integer(3)}}, closure([]Variable{p}, Expression{Value{p}, Value{Integer(2)}, BinaryOp{GreaterThan{}}}), BinaryOp{Any{}}}, Bool(true), "{1, 2, 3}.any($p -> $p > 2)"},
		{"any false", Expression{Value{Set{Integer(1), Integer(2), Integer(3)}}, closure([]Variable{p}, Expression{Value{p}, Value{Integer(3)}, BinaryOp{GreaterThan{}}}), BinaryOp{Any{}}}, Bool(false), "{1, 2, 3}.any($p -> $p > 3)"},
		{"nested closures", Expression{
			Value{Set{Integer(1), Integer(2), Integer(3)}},
			closure([]Variable{p}, Expression{
				Value{p}, Value{Integer(1)}, BinaryOp{GreaterThan{}},
				closure(nil, Expression{
					Value{Set{Integer(3), Integer(4), Integer(5)}},
					closure([]Variable{q}, Expression{Value{p}, Value{q}, BinaryOp{HeterogeneousEqual{}}}),
					BinaryOp{Any{}},
				}),
				BinaryOp{LazyAnd{}},
			}),
			BinaryOp{Any{}},
		}, Bool(true), "{1, 2, 3}.any($p -> $p > 1 && {3, 4, 5}.any($q -> $p == $q))"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			res, err := tc.expr.Evaluate(nil, syms)
			require.NoError(t, err)
			require.Equal(t, tc.want, res)
			require.Equal(t, tc.printed, tc.expr.Print(syms))
		})
	}

	// A closure parameter may not shadow a bound variable.
	shadow := Expression{Value{Set{Integer(1)}}, closure([]Variable{p}, Expression{Value{p}}), BinaryOp{Any{}}}
	var one Term = Integer(1)
	_, err := shadow.Evaluate(map[Variable]*Term{p: &one}, syms)
	require.ErrorIs(t, err, ErrShadowedVariable)

	// Errors inside an evaluated closure propagate.
	failing := Expression{Value{Bool(true)}, closure(nil, errorBody), BinaryOp{LazyAnd{}}}
	_, err = failing.Evaluate(nil, syms)
	require.Error(t, err)

	// A closure where a value is expected, and a value where a closure is.
	_, err = (&Expression{closure(nil, Expression{Value{Bool(true)}}), UnaryOp{Negate{}}}).Evaluate(nil, syms)
	require.Error(t, err)
	_, err = (&Expression{Value{Bool(true)}, Value{Bool(true)}, BinaryOp{LazyAnd{}}}).Evaluate(nil, syms)
	require.Error(t, err)
	_, err = (&Expression{Value{Bool(true)}, closure(nil, Expression{Value{Bool(true)}}), BinaryOp{Add{}}}).Evaluate(nil, syms)
	require.Error(t, err)
}

func TestUnaryTypeOf(t *testing.T) {
	syms := &SymbolTable{}
	require.Equal(t, UnaryTypeOf, TypeOf{}.Type())
	for _, tc := range []struct {
		value Term
		name  string
	}{
		{Integer(1), "integer"},
		{syms.Insert("test"), "string"},
		{Date(1), "date"},
		{Bytes{0xaa}, "bytes"},
		{Bool(true), "bool"},
		{Set{Bool(false), Bool(true)}, "set"},
		{Null{}, "null"},
		{Array{Integer(1)}, "array"},
		{NewMap(MapEntry{syms.Insert("a"), Bool(true)}), "map"},
	} {
		expr := Expression{Value{tc.value}, UnaryOp{TypeOf{}}}
		res, err := expr.Evaluate(nil, syms)
		require.NoError(t, err)
		require.Equal(t, syms.Insert(tc.name), res, tc.name)
		require.Equal(t, dbgTerm(syms, tc.value)+".type()", expr.Print(syms))
	}

	// A variable: evaluated on its value.
	var one Term = Integer(1)
	v := Variable(syms.Insert("t"))
	expr := Expression{Value{v}, UnaryOp{TypeOf{}}, Value{syms.Insert("integer")}, BinaryOp{HeterogeneousEqual{}}}
	res, err := expr.Evaluate(map[Variable]*Term{v: &one}, syms)
	require.NoError(t, err)
	require.Equal(t, Bool(true), res)
}

func dbgTerm(syms *SymbolTable, t Term) string {
	return SymbolDebugger{SymbolTable: syms}.Term(t)
}

func TestExternFuncs(t *testing.T) {
	syms := &SymbolTable{}
	name := syms.Insert("test")
	externs := ExternFuncs{
		"test": func(symbols *SymbolTable, left Term, right Term) (Term, error) {
			if right == nil {
				return left, nil
			}
			if left == right {
				return symbols.Insert("equal"), nil
			}
			return nil, errors.New("unsupported operands")
		},
	}

	unary := Expression{Value{Bool(true)}, UnaryOp{Ffi{Name: name}}}
	require.Equal(t, "true.extern::test()", unary.Print(syms))
	res, err := unary.EvaluateWith(nil, syms, externs)
	require.NoError(t, err)
	require.Equal(t, Bool(true), res)

	binary := Expression{Value{syms.Insert("a")}, Value{syms.Insert("a")}, BinaryOp{FfiBinary{Name: name}}}
	require.Equal(t, `"a".extern::test("a")`, binary.Print(syms))
	res, err = binary.EvaluateWith(nil, syms, externs)
	require.NoError(t, err)
	require.Equal(t, syms.Insert("equal"), res)

	// The function error is reported.
	failing := Expression{Value{Integer(1)}, Value{Integer(2)}, BinaryOp{FfiBinary{Name: name}}}
	_, err = failing.EvaluateWith(nil, syms, externs)
	require.ErrorContains(t, err, "unsupported operands")

	// Unknown name, and no registry at all.
	unknown := Expression{Value{Bool(true)}, UnaryOp{Ffi{Name: syms.Insert("other")}}}
	_, err = unknown.EvaluateWith(nil, syms, externs)
	require.ErrorIs(t, err, ErrUndefinedExtern)
	_, err = unary.Evaluate(nil, syms)
	require.ErrorIs(t, err, ErrUndefinedExtern)

	// Extern functions are visible inside closures.
	inClosure := Expression{
		Value{Set{Bool(true)}},
		Closure{Params: []Variable{Variable(syms.Insert("p"))}, Body: Expression{Value{Variable(syms.Insert("p"))}, UnaryOp{Ffi{Name: name}}}},
		BinaryOp{All{}},
	}
	res, err = inClosure.EvaluateWith(map[Variable]*Term{}, syms, externs)
	require.NoError(t, err)
	require.Equal(t, Bool(true), res)
}
