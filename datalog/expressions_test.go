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

func TestExpressions(t *testing.T) {
	ops := Expression{
		Value{Integer(1)},
		UnaryOp{Negate{}},
		Value{Variable(2)},
		BinaryOp{LessThan{}},
	}

	values := map[Variable]*ID{
		2: idptr(Integer(0)),
	}

	res, err := ops.Evaluate(values)
	require.NoError(t, err)
	require.Equal(t, Bool(true), res)
}

func TestWeirdExpressions(t *testing.T) {
	// add overflow
	ops := Expression{
		Value{Integer(math.MaxInt64)},
		Value{Integer(1)},
		BinaryOp{Add{}},
		Value{Integer(0)},
		BinaryOp{LessThan{}},
	}

	values := map[Variable]*ID{}

	res, err := ops.Evaluate(values)
	require.NoError(t, err)
	require.Equal(t, Bool(true), res)

	// div by 0
	ops = Expression{
		Value{Integer(42)},
		Value{Integer(0)},
		BinaryOp{Div{}},
	}
	_, err = ops.Evaluate(values)
	require.Equal(t, ErrExprDivByZero, errors.Unwrap(err))

	// mul overflow
	ops = Expression{
		Value{Integer(math.MaxInt64)},
		Value{Integer(math.MaxInt64)},
		BinaryOp{Mul{}},
		Value{Integer(1)},
		BinaryOp{Equal{}},
	}
	res, err = ops.Evaluate(values)
	require.NoError(t, err)
	require.Equal(t, Bool(true), res)
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
