package biscuit

import (
	"regexp"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/datalog"
	"github.com/stretchr/testify/require"
)

func TestFromDatalogFact(t *testing.T) {
	now := time.Now()

	symbolTable := &datalog.SymbolTable{"sym0", "sym1", "var1"}
	dlFact := datalog.Fact{
		Predicate: datalog.Predicate{
			Name: datalog.Symbol(0),
			IDs: []datalog.ID{
				datalog.Symbol(1),
				datalog.Integer(42),
				datalog.String("foo"),
				datalog.Variable(2),
				datalog.Date(now.Unix()),
				datalog.Bytes([]byte("some random bytes")),
			},
		},
	}

	fact, err := fromDatalogFact(symbolTable, dlFact)
	require.NoError(t, err)

	expectedFact := &Fact{
		Predicate: Predicate{
			Name: "sym0",
			IDs: []Term{
				Symbol("sym1"),
				Integer(42),
				String("foo"),
				Variable("var1"),
				Date(time.Unix(now.Unix(), 0)),
				Bytes([]byte("some random bytes")),
			},
		},
	}
	require.Equal(t, expectedFact, fact)
}

func TestConstraintsConvert(t *testing.T) {
	dlStringRegexpChecker := datalog.StringRegexpChecker(*regexp.MustCompile(`file[0-9]+\.txt`))
	now := time.Now()

	testCases := []struct {
		Desc            string
		Checker         Checker
		ExpectedChecker datalog.Checker
		SymbolTable     *datalog.SymbolTable
	}{
		{
			Desc:        "IntegerComparisonChecker",
			SymbolTable: &datalog.SymbolTable{},
			Checker: IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonEqual,
				Integer:    Integer(42),
			},
			ExpectedChecker: datalog.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonEqual,
				Integer:    datalog.Integer(42),
			},
		},
		{
			Desc:        "IntegerInChecker",
			SymbolTable: &datalog.SymbolTable{},
			Checker: IntegerInChecker{
				Set: map[Integer]struct{}{Integer(1): {}, Integer(2): {}, Integer(3): {}},
				Not: true,
			},
			ExpectedChecker: datalog.IntegerInChecker{
				Set: map[datalog.Integer]struct{}{datalog.Integer(1): {}, datalog.Integer(2): {}, datalog.Integer(3): {}},
				Not: true,
			},
		},
		{
			Desc:        "StringComparisonChecker",
			SymbolTable: &datalog.SymbolTable{},
			Checker: StringComparisonChecker{
				Comparison: datalog.StringComparisonSuffix,
				Str:        "foobar",
			},
			ExpectedChecker: datalog.StringComparisonChecker{
				Comparison: datalog.StringComparisonSuffix,
				Str:        "foobar",
			},
		},
		{
			Desc:        "StringInChecker",
			SymbolTable: &datalog.SymbolTable{},
			Checker: StringInChecker{
				Set: map[String]struct{}{String("abc"): {}, String("def"): {}},
				Not: false,
			},
			ExpectedChecker: datalog.StringInChecker{
				Set: map[datalog.String]struct{}{datalog.String("abc"): {}, datalog.String("def"): {}},
				Not: false,
			},
		},
		{
			Desc:            "StringRegexpChecker",
			SymbolTable:     &datalog.SymbolTable{},
			Checker:         StringRegexpChecker(*regexp.MustCompile(`file[0-9]+\.txt`)),
			ExpectedChecker: &dlStringRegexpChecker,
		},
		{
			Desc:        "DateComparisonChecker",
			SymbolTable: &datalog.SymbolTable{},
			Checker: DateComparisonChecker{
				Comparison: datalog.DateComparisonAfter,
				Date:       Date(now),
			},
			ExpectedChecker: datalog.DateComparisonChecker{
				Comparison: datalog.DateComparisonAfter,
				Date:       datalog.Date(now.Unix()),
			},
		},
		{
			Desc:        "SymbolInChecker",
			SymbolTable: &datalog.SymbolTable{"a", "b"},
			Checker: SymbolInChecker{
				Set: map[Symbol]struct{}{Symbol("a"): {}, Symbol("b"): {}},
				Not: true,
			},
			ExpectedChecker: datalog.SymbolInChecker{
				Set: map[datalog.Symbol]struct{}{datalog.Symbol(0): {}, datalog.Symbol(1): {}},
				Not: true,
			},
		},
		{
			Desc:        "BytesComparisonChecker",
			SymbolTable: &datalog.SymbolTable{},
			Checker: BytesComparisonChecker{
				Comparison: datalog.BytesComparisonEqual,
				Bytes:      []byte("some random bytes"),
			},
			ExpectedChecker: datalog.BytesComparisonChecker{
				Comparison: datalog.BytesComparisonEqual,
				Bytes:      []byte("some random bytes"),
			},
		},
		{
			Desc:        "BytesInChecker",
			SymbolTable: &datalog.SymbolTable{},
			Checker: BytesInChecker{
				Set: map[string]struct{}{"a": {}, "b": {}, "c": {}},
				Not: true,
			},
			ExpectedChecker: datalog.BytesInChecker{
				Set: map[string]struct{}{"a": {}, "b": {}, "c": {}},
				Not: true,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			v := testCase.SymbolTable.Insert("var1")
			c := Constraint{
				Name:    Variable("var1"),
				Checker: testCase.Checker,
			}

			dlConstraint := c.convert(testCase.SymbolTable)

			expectedConstraint := datalog.Constraint{
				Name:    datalog.Variable(v),
				Checker: testCase.ExpectedChecker,
			}

			require.Equal(t, expectedConstraint, dlConstraint)
		})
	}
}
