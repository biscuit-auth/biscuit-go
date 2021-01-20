package biscuit

import (
	"encoding/hex"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/flynn/biscuit-go/datalog"
	"github.com/flynn/biscuit-go/pb"
	"github.com/stretchr/testify/require"
)

func TestConstraintConvertDateComparison(t *testing.T) {
	now := time.Now()
	testCases := []struct {
		Desc     string
		Input    datalog.DateComparisonChecker
		Expected *pb.DateConstraint
	}{
		{
			Desc: "date comparison after",
			Input: datalog.DateComparisonChecker{
				Comparison: datalog.DateComparisonAfter,
				Date:       datalog.Date(now.Unix()),
			},
			Expected: &pb.DateConstraint{
				Kind:  pb.DateConstraint_AFTER,
				After: uint64(now.Unix()),
			},
		},
		{
			Desc: "date comparison before",
			Input: datalog.DateComparisonChecker{
				Comparison: datalog.DateComparisonBefore,
				Date:       datalog.Date(123456789),
			},
			Expected: &pb.DateConstraint{
				Kind:   pb.DateConstraint_BEFORE,
				Before: uint64(123456789),
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			i := rand.Uint32()

			in := &datalog.Constraint{
				Name:    datalog.Variable(i),
				Checker: testCase.Input,
			}
			out, err := tokenConstraintToProtoConstraint(*in)
			require.NoError(t, err)

			expected := &pb.Constraint{
				Id:   i,
				Kind: pb.Constraint_DATE,
				Date: testCase.Expected,
			}
			require.Equal(t, expected, out)

			dlout, err := protoConstraintToTokenConstraint(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertIntegerComparison(t *testing.T) {
	n := rand.Int63()
	testCases := []struct {
		Desc     string
		Input    datalog.IntegerComparisonChecker
		Expected *pb.IntConstraint
	}{
		{
			Desc: "int comparison equal",
			Input: datalog.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonEqual,
				Integer:    datalog.Integer(n),
			},
			Expected: &pb.IntConstraint{
				Kind:  pb.IntConstraint_EQUAL,
				Equal: n,
			},
		},
		{
			Desc: "int comparison larger",
			Input: datalog.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonGT,
				Integer:    datalog.Integer(n),
			},
			Expected: &pb.IntConstraint{
				Kind:   pb.IntConstraint_LARGER,
				Larger: n,
			},
		},
		{
			Desc: "int comparison larger or equal",
			Input: datalog.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonGTE,
				Integer:    datalog.Integer(n),
			},
			Expected: &pb.IntConstraint{
				Kind:          pb.IntConstraint_LARGER_OR_EQUAL,
				LargerOrEqual: n,
			},
		},
		{
			Desc: "int comparison lower",
			Input: datalog.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonLT,
				Integer:    datalog.Integer(n),
			},
			Expected: &pb.IntConstraint{
				Kind:  pb.IntConstraint_LOWER,
				Lower: n,
			},
		},
		{
			Desc: "int comparison lower or equal",
			Input: datalog.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonLTE,
				Integer:    datalog.Integer(n),
			},
			Expected: &pb.IntConstraint{
				Kind:         pb.IntConstraint_LOWER_OR_EQUAL,
				LowerOrEqual: n,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			i := rand.Uint32()
			in := &datalog.Constraint{
				Name:    datalog.Variable(i),
				Checker: testCase.Input,
			}

			out, err := tokenConstraintToProtoConstraint(*in)
			require.NoError(t, err)
			expected := &pb.Constraint{
				Id:   i,
				Kind: pb.Constraint_INT,
				Int:  testCase.Expected,
			}
			require.Equal(t, expected, out)

			dlout, err := protoConstraintToTokenConstraint(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertIntegerIn(t *testing.T) {
	n1 := rand.Int63()
	n2 := rand.Int63()
	n3 := rand.Int63()

	testCases := []struct {
		Desc     string
		Input    datalog.IntegerInChecker
		Expected *pb.IntConstraint
	}{
		{
			Desc: "int comparison in",
			Input: datalog.IntegerInChecker{
				Set: map[datalog.Integer]struct{}{
					datalog.Integer(n1): {},
					datalog.Integer(n2): {},
					datalog.Integer(n3): {},
				},
				Not: false,
			},
			Expected: &pb.IntConstraint{
				Kind:  pb.IntConstraint_IN,
				InSet: []int64{n1, n2, n3},
			},
		},
		{
			Desc: "int comparison not in",
			Input: datalog.IntegerInChecker{
				Set: map[datalog.Integer]struct{}{
					datalog.Integer(n1): {},
					datalog.Integer(n2): {},
					datalog.Integer(n3): {},
				},
				Not: true,
			},
			Expected: &pb.IntConstraint{
				Kind:     pb.IntConstraint_NOT_IN,
				NotInSet: []int64{n1, n2, n3},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			i := rand.Uint32()
			in := &datalog.Constraint{
				Name:    datalog.Variable(i),
				Checker: testCase.Input,
			}
			out, err := tokenConstraintToProtoConstraint(*in)
			require.NoError(t, err)
			expected := &pb.Constraint{
				Id:   i,
				Kind: pb.Constraint_INT,
				Int:  testCase.Expected,
			}

			sortIt := func(s []int64) {
				sort.Slice(s, func(i, j int) bool {
					return s[i] < s[j]
				})
			}

			sortIt(out.Int.InSet)
			sortIt(expected.Int.InSet)
			sortIt(out.Int.NotInSet)
			sortIt(expected.Int.NotInSet)

			require.Equal(t, expected, out)

			dlout, err := protoConstraintToTokenConstraint(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertStringComparison(t *testing.T) {
	testCases := []struct {
		Desc     string
		Input    datalog.StringComparisonChecker
		Expected *pb.StringConstraint
	}{
		{
			Desc: "string comparison equal",
			Input: datalog.StringComparisonChecker{
				Comparison: datalog.StringComparisonEqual,
				Str:        "abcd",
			},
			Expected: &pb.StringConstraint{
				Kind:  pb.StringConstraint_EQUAL,
				Equal: "abcd",
			},
		},
		{
			Desc: "string comparison prefix",
			Input: datalog.StringComparisonChecker{
				Comparison: datalog.StringComparisonPrefix,
				Str:        "abcd",
			},
			Expected: &pb.StringConstraint{
				Kind:   pb.StringConstraint_PREFIX,
				Prefix: "abcd",
			},
		},
		{
			Desc: "string comparison suffix",
			Input: datalog.StringComparisonChecker{
				Comparison: datalog.StringComparisonSuffix,
				Str:        "abcd",
			},
			Expected: &pb.StringConstraint{
				Kind:   pb.StringConstraint_SUFFIX,
				Suffix: "abcd",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			i := rand.Uint32()
			in := &datalog.Constraint{
				Name:    datalog.Variable(i),
				Checker: testCase.Input,
			}
			out, err := tokenConstraintToProtoConstraint(*in)
			require.NoError(t, err)
			expected := &pb.Constraint{
				Id:   i,
				Kind: pb.Constraint_STRING,
				Str:  testCase.Expected,
			}
			require.Equal(t, expected, out)

			dlout, err := protoConstraintToTokenConstraint(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertStringIn(t *testing.T) {
	s1 := "abcd"
	s2 := "efgh"

	testCases := []struct {
		Desc     string
		Input    datalog.StringInChecker
		Expected *pb.StringConstraint
	}{
		{
			Desc: "string comparison in",
			Input: datalog.StringInChecker{
				Set: map[datalog.String]struct{}{datalog.String(s1): {}, datalog.String(s2): {}},
				Not: false,
			},
			Expected: &pb.StringConstraint{
				Kind:  pb.StringConstraint_IN,
				InSet: []string{s1, s2},
			},
		},
		{
			Desc: "string comparison not in",
			Input: datalog.StringInChecker{
				Set: map[datalog.String]struct{}{datalog.String(s1): {}, datalog.String(s2): {}},
				Not: true,
			},
			Expected: &pb.StringConstraint{
				Kind:     pb.StringConstraint_NOT_IN,
				NotInSet: []string{s1, s2},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			i := rand.Uint32()
			in := &datalog.Constraint{
				Name:    datalog.Variable(i),
				Checker: testCase.Input,
			}
			out, err := tokenConstraintToProtoConstraint(*in)
			require.NoError(t, err)
			expected := &pb.Constraint{
				Id:   i,
				Kind: pb.Constraint_STRING,
				Str:  testCase.Expected,
			}

			sort.Strings(expected.Str.InSet)
			sort.Strings(out.Str.InSet)
			sort.Strings(expected.Str.NotInSet)
			sort.Strings(out.Str.NotInSet)

			require.Equal(t, expected, out)

			dlout, err := protoConstraintToTokenConstraint(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertStringRegexp(t *testing.T) {
	re := regexp.MustCompile(`[a-z0-9_]+`)
	dlre := datalog.StringRegexpChecker(*re)

	testCases := []struct {
		Desc     string
		Input    *datalog.StringRegexpChecker
		Expected *pb.StringConstraint
	}{
		{
			Desc:  "string regexp",
			Input: &dlre,
			Expected: &pb.StringConstraint{
				Kind:  pb.StringConstraint_REGEX,
				Regex: re.String(),
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			i := rand.Uint32()
			in := &datalog.Constraint{
				Name:    datalog.Variable(i),
				Checker: testCase.Input,
			}
			out, err := tokenConstraintToProtoConstraint(*in)
			require.NoError(t, err)
			expected := &pb.Constraint{
				Id:   i,
				Kind: pb.Constraint_STRING,
				Str:  testCase.Expected,
			}
			require.Equal(t, expected, out)

			dlout, err := protoConstraintToTokenConstraint(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertBytesComparison(t *testing.T) {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	require.NoError(t, err)

	testCases := []struct {
		Desc     string
		Input    datalog.BytesComparisonChecker
		Expected *pb.BytesConstraint
	}{
		{
			Desc: "bytes comparison equal",
			Input: datalog.BytesComparisonChecker{
				Comparison: datalog.BytesComparisonEqual,
				Bytes:      b,
			},
			Expected: &pb.BytesConstraint{
				Kind:  pb.BytesConstraint_EQUAL,
				Equal: b,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			i := rand.Uint32()
			in := &datalog.Constraint{
				Name:    datalog.Variable(i),
				Checker: testCase.Input,
			}
			out, err := tokenConstraintToProtoConstraint(*in)
			require.NoError(t, err)
			expected := &pb.Constraint{
				Id:    i,
				Kind:  pb.Constraint_BYTES,
				Bytes: testCase.Expected,
			}
			require.Equal(t, expected, out)

			dlout, err := protoConstraintToTokenConstraint(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertBytesIn(t *testing.T) {
	b1 := make([]byte, 64)
	_, err := rand.Read(b1)
	require.NoError(t, err)

	b2 := make([]byte, 128)
	_, err = rand.Read(b2)
	require.NoError(t, err)

	testCases := []struct {
		Desc     string
		Input    datalog.BytesInChecker
		Expected *pb.BytesConstraint
	}{
		{
			Desc: "bytes in",
			Input: datalog.BytesInChecker{
				Set: map[string]struct{}{hex.EncodeToString(b1): {}, hex.EncodeToString(b2): {}},
				Not: false,
			},
			Expected: &pb.BytesConstraint{
				Kind:  pb.BytesConstraint_IN,
				InSet: [][]byte{b1, b2},
			},
		},
		{
			Desc: "bytes not in",
			Input: datalog.BytesInChecker{
				Set: map[string]struct{}{hex.EncodeToString(b1): {}, hex.EncodeToString(b2): {}},
				Not: true,
			},
			Expected: &pb.BytesConstraint{
				Kind:     pb.BytesConstraint_NOT_IN,
				NotInSet: [][]byte{b1, b2},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			i := rand.Uint32()
			in := &datalog.Constraint{
				Name:    datalog.Variable(i),
				Checker: testCase.Input,
			}
			out, err := tokenConstraintToProtoConstraint(*in)
			require.NoError(t, err)
			expected := &pb.Constraint{
				Id:    i,
				Kind:  pb.Constraint_BYTES,
				Bytes: testCase.Expected,
			}

			sortIt := func(s [][]byte) {
				sort.Slice(s, func(i, j int) bool {
					return strings.Compare(hex.EncodeToString(s[i]), hex.EncodeToString(s[j])) < 0
				})
			}

			sortIt(out.Bytes.InSet)
			sortIt(expected.Bytes.InSet)
			sortIt(out.Bytes.NotInSet)
			sortIt(expected.Bytes.NotInSet)

			require.Equal(t, expected, out)

			dlout, err := protoConstraintToTokenConstraint(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertSymbolIn(t *testing.T) {
	s1 := rand.Uint64()
	s2 := rand.Uint64()
	s3 := rand.Uint64()

	testCases := []struct {
		Desc     string
		Input    datalog.SymbolInChecker
		Expected *pb.SymbolConstraint
	}{
		{
			Desc: "symbol in",
			Input: datalog.SymbolInChecker{
				Set: map[datalog.Symbol]struct{}{
					datalog.Symbol(s1): {},
					datalog.Symbol(s2): {},
					datalog.Symbol(s3): {},
				},
				Not: false,
			},
			Expected: &pb.SymbolConstraint{
				Kind:  pb.SymbolConstraint_IN,
				InSet: []uint64{s1, s2, s3},
			},
		},
		{
			Desc: "symbol not in",
			Input: datalog.SymbolInChecker{
				Set: map[datalog.Symbol]struct{}{
					datalog.Symbol(s1): {},
					datalog.Symbol(s2): {},
					datalog.Symbol(s3): {},
				},
				Not: true,
			},
			Expected: &pb.SymbolConstraint{
				Kind:     pb.SymbolConstraint_NOT_IN,
				NotInSet: []uint64{s1, s2, s3},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			i := rand.Uint32()
			in := &datalog.Constraint{
				Name:    datalog.Variable(i),
				Checker: testCase.Input,
			}
			out, err := tokenConstraintToProtoConstraint(*in)
			require.NoError(t, err)
			expected := &pb.Constraint{
				Id:     i,
				Kind:   pb.Constraint_SYMBOL,
				Symbol: testCase.Expected,
			}

			sortIt := func(s []uint64) {
				sort.Slice(s, func(i, j int) bool {
					return s[i] < s[j]
				})
			}

			sortIt(out.Symbol.InSet)
			sortIt(expected.Symbol.InSet)
			sortIt(out.Symbol.NotInSet)
			sortIt(expected.Symbol.NotInSet)

			require.Equal(t, expected, out)

			dlout, err := protoConstraintToTokenConstraint(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestRuleConvert(t *testing.T) {
	now := time.Now()

	in := &datalog.Rule{
		Head: datalog.Predicate{
			Name: datalog.Symbol(42),
			IDs:  []datalog.ID{datalog.Integer(1), datalog.String("id_1")},
		},
		Body: []datalog.Predicate{
			{
				Name: datalog.Symbol(43),
				IDs:  []datalog.ID{datalog.Symbol(2), datalog.Date(now.Unix())},
			}, {
				Name: datalog.Symbol(44),
				IDs:  []datalog.ID{datalog.Bytes([]byte("abcd"))},
			},
		},
		Constraints: []datalog.Constraint{
			{
				Name: datalog.Variable(9),
				Checker: datalog.IntegerComparisonChecker{
					Comparison: datalog.IntegerComparisonEqual,
					Integer:    42,
				},
			}, {
				Name: datalog.Variable(99),
				Checker: datalog.StringComparisonChecker{
					Comparison: datalog.StringComparisonPrefix,
					Str:        "abcd",
				},
			},
		},
	}

	expectedPbRule := &pb.Rule{
		Head: &pb.Predicate{Name: 42, Ids: []*pb.ID{{Kind: pb.ID_INTEGER, Integer: 1}, {Kind: pb.ID_STR, Str: "id_1"}}},
		Body: []*pb.Predicate{
			{Name: 43, Ids: []*pb.ID{{Kind: pb.ID_SYMBOL, Symbol: 2}, {Kind: pb.ID_DATE, Date: uint64(now.Unix())}}},
			{Name: 44, Ids: []*pb.ID{{Kind: pb.ID_BYTES, Bytes: []byte("abcd")}}},
		},
		Constraints: []*pb.Constraint{
			{Id: 9, Kind: pb.Constraint_INT, Int: &pb.IntConstraint{Kind: pb.IntConstraint_EQUAL, Equal: 42}},
			{Id: 99, Kind: pb.Constraint_STRING, Str: &pb.StringConstraint{Kind: pb.StringConstraint_PREFIX, Prefix: "abcd"}},
		},
	}

	pbRule, err := tokenRuleToProtoRule(*in)
	require.NoError(t, err)
	require.Equal(t, expectedPbRule, pbRule)
	out, err := protoRuleToTokenRule(pbRule)
	require.NoError(t, err)
	require.Equal(t, in, out)
}

func TestFactConvert(t *testing.T) {
	now := time.Now()
	in := &datalog.Fact{Predicate: datalog.Predicate{
		Name: datalog.Symbol(42),
		IDs: []datalog.ID{
			datalog.Symbol(1),
			datalog.Integer(2),
			datalog.Variable(3),
			datalog.Bytes([]byte("bytes")),
			datalog.String("abcd"),
			datalog.Date(now.Unix()),
		},
	}}

	expectedPbFact := &pb.Fact{Predicate: &pb.Predicate{
		Name: 42,
		Ids: []*pb.ID{
			{Kind: pb.ID_SYMBOL, Symbol: 1},
			{Kind: pb.ID_INTEGER, Integer: 2},
			{Kind: pb.ID_VARIABLE, Variable: 3},
			{Kind: pb.ID_BYTES, Bytes: []byte("bytes")},
			{Kind: pb.ID_STR, Str: "abcd"},
			{Kind: pb.ID_DATE, Date: uint64(now.Unix())},
		},
	}}

	pbFact, err := tokenFactToProtoFact(*in)
	require.NoError(t, err)
	require.Equal(t, expectedPbFact, pbFact)

	out, err := protoFactToTokenFact(pbFact)
	require.NoError(t, err)
	require.Equal(t, in, out)
}

func TestBlockConvert(t *testing.T) {
	predicate := datalog.Predicate{
		Name: datalog.Symbol(12),
		IDs:  []datalog.ID{datalog.String("abcd")},
	}

	pbPredicate := &pb.Predicate{
		Name: 12,
		Ids:  []*pb.ID{{Kind: pb.ID_STR, Str: "abcd"}},
	}

	rule := &datalog.Rule{
		Head: predicate,
		Body: []datalog.Predicate{predicate},
		Constraints: []datalog.Constraint{
			{
				Name: datalog.Variable(13),
				Checker: datalog.IntegerComparisonChecker{
					Comparison: datalog.IntegerComparisonEqual,
					Integer:    1234,
				},
			},
		},
	}

	pbRule := &pb.Rule{
		Head: pbPredicate,
		Body: []*pb.Predicate{pbPredicate},
		Constraints: []*pb.Constraint{
			{
				Id:   13,
				Kind: pb.Constraint_INT,
				Int:  &pb.IntConstraint{Kind: pb.IntConstraint_EQUAL, Equal: 1234},
			},
		},
	}

	in := &Block{
		index:   42,
		symbols: &datalog.SymbolTable{"a", "b", "c", "d"},
		facts:   &datalog.FactSet{datalog.Fact{Predicate: predicate}},
		rules:   []datalog.Rule{*rule},
		caveats: []datalog.Caveat{{Queries: []datalog.Rule{*rule}}},
		context: "context",
	}

	expectedPbBlock := &pb.Block{
		Index:   42,
		Symbols: []string{"a", "b", "c", "d"},
		Facts: []*pb.Fact{
			{Predicate: pbPredicate},
		},
		Rules:   []*pb.Rule{pbRule},
		Caveats: []*pb.Caveat{{Queries: []*pb.Rule{pbRule}}},
		Context: "context",
	}

	pbBlock, err := tokenBlockToProtoBlock(in)
	require.NoError(t, err)
	require.Equal(t, expectedPbBlock, pbBlock)

	out, err := protoBlockToTokenBlock(pbBlock)
	require.NoError(t, err)
	require.Equal(t, in, out)

	pbBlock.Version = MaxSchemaVersion + 1
	_, err = protoBlockToTokenBlock(pbBlock)
	require.Error(t, err)
}
