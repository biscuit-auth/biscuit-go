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

func TestConstraintConvertDateComparisonV0(t *testing.T) {
	now := time.Now()
	testCases := []struct {
		Desc     string
		Input    datalog.DateComparisonChecker
		Expected *pb.DateConstraintV0
	}{
		{
			Desc: "date comparison after",
			Input: datalog.DateComparisonChecker{
				Comparison: datalog.DateComparisonAfter,
				Date:       datalog.Date(now.Unix()),
			},
			Expected: &pb.DateConstraintV0{
				Kind:  pb.DateConstraintV0_AFTER,
				After: uint64(now.Unix()),
			},
		},
		{
			Desc: "date comparison before",
			Input: datalog.DateComparisonChecker{
				Comparison: datalog.DateComparisonBefore,
				Date:       datalog.Date(123456789),
			},
			Expected: &pb.DateConstraintV0{
				Kind:   pb.DateConstraintV0_BEFORE,
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
			out, err := tokenConstraintToProtoConstraintV0(*in)
			require.NoError(t, err)

			expected := &pb.ConstraintV0{
				Id:   i,
				Kind: pb.ConstraintV0_DATE,
				Date: testCase.Expected,
			}
			require.Equal(t, expected, out)

			dlout, err := protoConstraintToTokenConstraintV0(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertIntegerComparisonV0(t *testing.T) {
	n := rand.Int63()
	testCases := []struct {
		Desc     string
		Input    datalog.IntegerComparisonChecker
		Expected *pb.IntConstraintV0
	}{
		{
			Desc: "int comparison equal",
			Input: datalog.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonEqual,
				Integer:    datalog.Integer(n),
			},
			Expected: &pb.IntConstraintV0{
				Kind:  pb.IntConstraintV0_EQUAL,
				Equal: n,
			},
		},
		{
			Desc: "int comparison larger",
			Input: datalog.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonGT,
				Integer:    datalog.Integer(n),
			},
			Expected: &pb.IntConstraintV0{
				Kind:   pb.IntConstraintV0_LARGER,
				Larger: n,
			},
		},
		{
			Desc: "int comparison larger or equal",
			Input: datalog.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonGTE,
				Integer:    datalog.Integer(n),
			},
			Expected: &pb.IntConstraintV0{
				Kind:          pb.IntConstraintV0_LARGER_OR_EQUAL,
				LargerOrEqual: n,
			},
		},
		{
			Desc: "int comparison lower",
			Input: datalog.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonLT,
				Integer:    datalog.Integer(n),
			},
			Expected: &pb.IntConstraintV0{
				Kind:  pb.IntConstraintV0_LOWER,
				Lower: n,
			},
		},
		{
			Desc: "int comparison lower or equal",
			Input: datalog.IntegerComparisonChecker{
				Comparison: datalog.IntegerComparisonLTE,
				Integer:    datalog.Integer(n),
			},
			Expected: &pb.IntConstraintV0{
				Kind:         pb.IntConstraintV0_LOWER_OR_EQUAL,
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

			out, err := tokenConstraintToProtoConstraintV0(*in)
			require.NoError(t, err)
			expected := &pb.ConstraintV0{
				Id:   i,
				Kind: pb.ConstraintV0_INT,
				Int:  testCase.Expected,
			}
			require.Equal(t, expected, out)

			dlout, err := protoConstraintToTokenConstraintV0(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertIntegerInV0(t *testing.T) {
	n1 := rand.Int63()
	n2 := rand.Int63()
	n3 := rand.Int63()

	testCases := []struct {
		Desc     string
		Input    datalog.IntegerInChecker
		Expected *pb.IntConstraintV0
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
			Expected: &pb.IntConstraintV0{
				Kind:  pb.IntConstraintV0_IN,
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
			Expected: &pb.IntConstraintV0{
				Kind:     pb.IntConstraintV0_NOT_IN,
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
			out, err := tokenConstraintToProtoConstraintV0(*in)
			require.NoError(t, err)
			expected := &pb.ConstraintV0{
				Id:   i,
				Kind: pb.ConstraintV0_INT,
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

			dlout, err := protoConstraintToTokenConstraintV0(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertStringComparisonV0(t *testing.T) {
	testCases := []struct {
		Desc     string
		Input    datalog.StringComparisonChecker
		Expected *pb.StringConstraintV0
	}{
		{
			Desc: "string comparison equal",
			Input: datalog.StringComparisonChecker{
				Comparison: datalog.StringComparisonEqual,
				Str:        "abcd",
			},
			Expected: &pb.StringConstraintV0{
				Kind:  pb.StringConstraintV0_EQUAL,
				Equal: "abcd",
			},
		},
		{
			Desc: "string comparison prefix",
			Input: datalog.StringComparisonChecker{
				Comparison: datalog.StringComparisonPrefix,
				Str:        "abcd",
			},
			Expected: &pb.StringConstraintV0{
				Kind:   pb.StringConstraintV0_PREFIX,
				Prefix: "abcd",
			},
		},
		{
			Desc: "string comparison suffix",
			Input: datalog.StringComparisonChecker{
				Comparison: datalog.StringComparisonSuffix,
				Str:        "abcd",
			},
			Expected: &pb.StringConstraintV0{
				Kind:   pb.StringConstraintV0_SUFFIX,
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
			out, err := tokenConstraintToProtoConstraintV0(*in)
			require.NoError(t, err)
			expected := &pb.ConstraintV0{
				Id:   i,
				Kind: pb.ConstraintV0_STRING,
				Str:  testCase.Expected,
			}
			require.Equal(t, expected, out)

			dlout, err := protoConstraintToTokenConstraintV0(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertStringInV0(t *testing.T) {
	s1 := "abcd"
	s2 := "efgh"

	testCases := []struct {
		Desc     string
		Input    datalog.StringInChecker
		Expected *pb.StringConstraintV0
	}{
		{
			Desc: "string comparison in",
			Input: datalog.StringInChecker{
				Set: map[datalog.String]struct{}{datalog.String(s1): {}, datalog.String(s2): {}},
				Not: false,
			},
			Expected: &pb.StringConstraintV0{
				Kind:  pb.StringConstraintV0_IN,
				InSet: []string{s1, s2},
			},
		},
		{
			Desc: "string comparison not in",
			Input: datalog.StringInChecker{
				Set: map[datalog.String]struct{}{datalog.String(s1): {}, datalog.String(s2): {}},
				Not: true,
			},
			Expected: &pb.StringConstraintV0{
				Kind:     pb.StringConstraintV0_NOT_IN,
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
			out, err := tokenConstraintToProtoConstraintV0(*in)
			require.NoError(t, err)
			expected := &pb.ConstraintV0{
				Id:   i,
				Kind: pb.ConstraintV0_STRING,
				Str:  testCase.Expected,
			}

			sort.Strings(expected.Str.InSet)
			sort.Strings(out.Str.InSet)
			sort.Strings(expected.Str.NotInSet)
			sort.Strings(out.Str.NotInSet)

			require.Equal(t, expected, out)

			dlout, err := protoConstraintToTokenConstraintV0(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertStringRegexpV0(t *testing.T) {
	re := regexp.MustCompile(`[a-z0-9_]+`)
	dlre := datalog.StringRegexpChecker(*re)

	testCases := []struct {
		Desc     string
		Input    *datalog.StringRegexpChecker
		Expected *pb.StringConstraintV0
	}{
		{
			Desc:  "string regexp",
			Input: &dlre,
			Expected: &pb.StringConstraintV0{
				Kind:  pb.StringConstraintV0_REGEX,
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
			out, err := tokenConstraintToProtoConstraintV0(*in)
			require.NoError(t, err)
			expected := &pb.ConstraintV0{
				Id:   i,
				Kind: pb.ConstraintV0_STRING,
				Str:  testCase.Expected,
			}
			require.Equal(t, expected, out)

			dlout, err := protoConstraintToTokenConstraintV0(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertBytesComparisonV0(t *testing.T) {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	require.NoError(t, err)

	testCases := []struct {
		Desc     string
		Input    datalog.BytesComparisonChecker
		Expected *pb.BytesConstraintV0
	}{
		{
			Desc: "bytes comparison equal",
			Input: datalog.BytesComparisonChecker{
				Comparison: datalog.BytesComparisonEqual,
				Bytes:      b,
			},
			Expected: &pb.BytesConstraintV0{
				Kind:  pb.BytesConstraintV0_EQUAL,
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
			out, err := tokenConstraintToProtoConstraintV0(*in)
			require.NoError(t, err)
			expected := &pb.ConstraintV0{
				Id:    i,
				Kind:  pb.ConstraintV0_BYTES,
				Bytes: testCase.Expected,
			}
			require.Equal(t, expected, out)

			dlout, err := protoConstraintToTokenConstraintV0(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertBytesInV0(t *testing.T) {
	b1 := make([]byte, 64)
	_, err := rand.Read(b1)
	require.NoError(t, err)

	b2 := make([]byte, 128)
	_, err = rand.Read(b2)
	require.NoError(t, err)

	testCases := []struct {
		Desc     string
		Input    datalog.BytesInChecker
		Expected *pb.BytesConstraintV0
	}{
		{
			Desc: "bytes in",
			Input: datalog.BytesInChecker{
				Set: map[string]struct{}{hex.EncodeToString(b1): {}, hex.EncodeToString(b2): {}},
				Not: false,
			},
			Expected: &pb.BytesConstraintV0{
				Kind:  pb.BytesConstraintV0_IN,
				InSet: [][]byte{b1, b2},
			},
		},
		{
			Desc: "bytes not in",
			Input: datalog.BytesInChecker{
				Set: map[string]struct{}{hex.EncodeToString(b1): {}, hex.EncodeToString(b2): {}},
				Not: true,
			},
			Expected: &pb.BytesConstraintV0{
				Kind:     pb.BytesConstraintV0_NOT_IN,
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
			out, err := tokenConstraintToProtoConstraintV0(*in)
			require.NoError(t, err)
			expected := &pb.ConstraintV0{
				Id:    i,
				Kind:  pb.ConstraintV0_BYTES,
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

			dlout, err := protoConstraintToTokenConstraintV0(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestConstraintConvertSymbolInV0(t *testing.T) {
	s1 := rand.Uint64()
	s2 := rand.Uint64()
	s3 := rand.Uint64()

	testCases := []struct {
		Desc     string
		Input    datalog.SymbolInChecker
		Expected *pb.SymbolConstraintV0
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
			Expected: &pb.SymbolConstraintV0{
				Kind:  pb.SymbolConstraintV0_IN,
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
			Expected: &pb.SymbolConstraintV0{
				Kind:     pb.SymbolConstraintV0_NOT_IN,
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
			out, err := tokenConstraintToProtoConstraintV0(*in)
			require.NoError(t, err)
			expected := &pb.ConstraintV0{
				Id:     i,
				Kind:   pb.ConstraintV0_SYMBOL,
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

			dlout, err := protoConstraintToTokenConstraintV0(out)
			require.NoError(t, err)
			require.Equal(t, in, dlout)
		})
	}
}

func TestRuleConvertV0(t *testing.T) {
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

	expectedPbRule := &pb.RuleV0{
		Head: &pb.PredicateV0{Name: 42, Ids: []*pb.IDV0{{Kind: pb.IDV0_INTEGER, Integer: 1}, {Kind: pb.IDV0_STR, Str: "id_1"}}},
		Body: []*pb.PredicateV0{
			{Name: 43, Ids: []*pb.IDV0{{Kind: pb.IDV0_SYMBOL, Symbol: 2}, {Kind: pb.IDV0_DATE, Date: uint64(now.Unix())}}},
			{Name: 44, Ids: []*pb.IDV0{{Kind: pb.IDV0_BYTES, Bytes: []byte("abcd")}}},
		},
		Constraints: []*pb.ConstraintV0{
			{Id: 9, Kind: pb.ConstraintV0_INT, Int: &pb.IntConstraintV0{Kind: pb.IntConstraintV0_EQUAL, Equal: 42}},
			{Id: 99, Kind: pb.ConstraintV0_STRING, Str: &pb.StringConstraintV0{Kind: pb.StringConstraintV0_PREFIX, Prefix: "abcd"}},
		},
	}

	pbRule, err := tokenRuleToProtoRuleV0(*in)
	require.NoError(t, err)
	require.Equal(t, expectedPbRule, pbRule)
	out, err := protoRuleToTokenRuleV0(pbRule)
	require.NoError(t, err)
	require.Equal(t, in, out)
}

func TestFactConvertV0(t *testing.T) {
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

	expectedPbFact := &pb.FactV0{Predicate: &pb.PredicateV0{
		Name: 42,
		Ids: []*pb.IDV0{
			{Kind: pb.IDV0_SYMBOL, Symbol: 1},
			{Kind: pb.IDV0_INTEGER, Integer: 2},
			{Kind: pb.IDV0_VARIABLE, Variable: 3},
			{Kind: pb.IDV0_BYTES, Bytes: []byte("bytes")},
			{Kind: pb.IDV0_STR, Str: "abcd"},
			{Kind: pb.IDV0_DATE, Date: uint64(now.Unix())},
		},
	}}

	pbFact, err := tokenFactToProtoFactV0(*in)
	require.NoError(t, err)
	require.Equal(t, expectedPbFact, pbFact)

	out, err := protoFactToTokenFactV0(pbFact)
	require.NoError(t, err)
	require.Equal(t, in, out)
}

func TestBlockConvertV0(t *testing.T) {
	predicate := datalog.Predicate{
		Name: datalog.Symbol(12),
		IDs:  []datalog.ID{datalog.String("abcd")},
	}

	pbPredicate := &pb.PredicateV0{
		Name: 12,
		Ids:  []*pb.IDV0{{Kind: pb.IDV0_STR, Str: "abcd"}},
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

	pbRule := &pb.RuleV0{
		Head: pbPredicate,
		Body: []*pb.PredicateV0{pbPredicate},
		Constraints: []*pb.ConstraintV0{
			{
				Id:   13,
				Kind: pb.ConstraintV0_INT,
				Int:  &pb.IntConstraintV0{Kind: pb.IntConstraintV0_EQUAL, Equal: 1234},
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
		FactsV0: []*pb.FactV0{
			{Predicate: pbPredicate},
		},
		RulesV0:   []*pb.RuleV0{pbRule},
		CaveatsV0: []*pb.CaveatV0{{Queries: []*pb.RuleV0{pbRule}}},
		Context:   "context",
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
