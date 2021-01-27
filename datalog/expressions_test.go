package datalog

import (
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func idptr(v ID) *ID {
	return &v
}

func TestNegate(t *testing.T) {
	ops := Expression{
		Value{Bool(true)},
		UnaryOp{Negate{}},
		UnaryOp{Negate{}},
	}

	res, err := ops.Evaluate(nil)
	require.NoError(t, err)
	require.Equal(t, Bool(true), res)
}

func TestAdd(t *testing.T) {
	testCases := []struct {
		desc        string
		left        int64
		right       int64
		res         int64
		expectedErr error
	}{
		{
			desc:  "normal addition",
			left:  5,
			right: 3,
			res:   8,
		},
		{
			desc:  "addition with negative numbers",
			left:  10,
			right: -7,
			res:   3,
		},
		{
			desc:  "addition with negative numbers 2",
			left:  -7,
			right: -3,
			res:   -10,
		},
		{
			desc:        "handle overflow errors",
			left:        math.MaxInt64,
			right:       1,
			expectedErr: ErrInt64Overflow,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{Integer(tc.left)},
				Value{Integer(tc.right)},
				BinaryOp{Add{}},
				Value{Integer(tc.res)},
				BinaryOp{Equal{}},
			}

			res, err := ops.Evaluate(nil)
			require.Equal(t, tc.expectedErr, errors.Unwrap(err))
			if tc.expectedErr == nil {
				require.Equal(t, Bool(true), res)
			}
		})
	}
}

func TestSub(t *testing.T) {
	testCases := []struct {
		desc        string
		left        int64
		right       int64
		res         int64
		expectedErr error
	}{
		{
			desc:  "normal substraction",
			left:  5,
			right: 3,
			res:   2,
		},
		{
			desc:  "substraction with negative numbers",
			left:  10,
			right: -7,
			res:   17,
		},
		{
			desc:  "substraction with negative numbers 2",
			left:  -7,
			right: -3,
			res:   -4,
		},
		{
			desc:        "handle overflow errors",
			left:        math.MinInt64,
			right:       1,
			expectedErr: ErrInt64Overflow,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{Integer(tc.left)},
				Value{Integer(tc.right)},
				BinaryOp{Sub{}},
				Value{Integer(tc.res)},
				BinaryOp{Equal{}},
			}

			res, err := ops.Evaluate(nil)
			require.Equal(t, tc.expectedErr, errors.Unwrap(err))
			if tc.expectedErr == nil {
				require.Equal(t, Bool(true), res)
			}
		})
	}
}

func TestDiv(t *testing.T) {
	t.Run("regular division", func(t *testing.T) {
		ops := Expression{
			Value{Integer(32)},
			Value{Integer(4)},
			BinaryOp{Div{}},
			Value{Integer(8)},
			BinaryOp{Equal{}},
		}

		res, err := ops.Evaluate(nil)
		require.NoError(t, err)
		require.Equal(t, Bool(true), res)
	})

	t.Run("div by zero", func(t *testing.T) {
		ops := Expression{
			Value{Integer(42)},
			Value{Integer(0)},
			BinaryOp{Div{}},
		}
		_, err := ops.Evaluate(nil)
		require.Equal(t, ErrExprDivByZero, errors.Unwrap(err))

	})
}

func TestMul(t *testing.T) {
	testCases := []struct {
		desc        string
		left        int64
		right       int64
		res         int64
		expectedErr error
	}{
		{
			desc:  "normal multiplication",
			left:  5,
			right: 3,
			res:   15,
		},
		{
			desc:  "multiplication with negative numbers",
			left:  10,
			right: -7,
			res:   -70,
		},
		{
			desc:  "multiplication with negative numbers 2",
			left:  -7,
			right: -3,
			res:   21,
		},
		{
			desc:        "handle overflow errors",
			left:        math.MaxInt64,
			right:       math.MaxInt64,
			expectedErr: ErrInt64Overflow,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ops := Expression{
				Value{Integer(tc.left)},
				Value{Integer(tc.right)},
				BinaryOp{Mul{}},
				Value{Integer(tc.res)},
				BinaryOp{Equal{}},
			}

			res, err := ops.Evaluate(nil)
			require.Equal(t, tc.expectedErr, errors.Unwrap(err))
			if tc.expectedErr == nil {
				require.Equal(t, Bool(true), res)
			}
		})
	}
}

func TestExpressionParens(t *testing.T) {
	ops := Expression{
		Value{Integer(1)},
		Value{Variable(2)},
		Value{Integer(3)},
		BinaryOp{Mul{}},
		BinaryOp{Add{}},
	}

	values := map[Variable]*ID{
		2: idptr(Integer(2)),
	}

	res, err := ops.Evaluate(values)
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

	res, err = ops.Evaluate(values)
	require.NoError(t, err)
	require.Equal(t, Integer(9), res)
}

func TestIn(t *testing.T) {
	tests := []struct {
		name    string
		left    ID
		right   Set
		want    ID
		wantErr bool
	}{
		{
			name:  "integer in set",
			left:  Integer(1),
			right: Set{Integer(1), Integer(2), Integer(3)},
			want:  Bool(true),
		},
		{
			name:  "string not in set",
			left:  String("abc"),
			right: Set{String("def"), String("ijk")},
			want:  Bool(false),
		},
		{
			name:  "bytes in set",
			left:  Bytes("abc"),
			right: Set{Bytes("abc"), Bytes("def")},
			want:  Bool(true),
		},
		{
			name:  "symbol not in set",
			left:  Symbol(0),
			right: Set{Symbol(1), Symbol(2)},
			want:  Bool(false),
		},
		{
			name:    "set element type mismatch",
			left:    Symbol(0),
			right:   Set{Integer(1), Integer(2)},
			wantErr: true,
		},
		{
			name:    "unsupported type Bool",
			left:    Bool(true),
			right:   Set{Bool(true), Bool(false)},
			wantErr: true,
		},
		{
			name:    "unsupported type Date",
			left:    Date(0),
			right:   Set{Date(1), Date(2)},
			wantErr: true,
		},
		{
			name:    "unsupported type Set",
			left:    Set{Integer(0)},
			right:   Set{Integer(1), Integer(2)},
			wantErr: true,
		},
		{
			name:    "unsupported type Set",
			left:    Variable(0),
			right:   Set{Variable(1), Variable(2)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := In{}.Eval(tt.left, tt.right)
			require.Equal(t, tt.wantErr, (err != nil))
			require.Equal(t, tt.want, got)
		})
	}
}
