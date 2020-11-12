package parser

import (
	"testing"

	"github.com/alecthomas/participle"
	"github.com/stretchr/testify/require"
)

func TestGrammarPredicate(t *testing.T) {
	parser, err := participle.Build(&Predicate{}, defaultParserOptions...)
	require.NoError(t, err)

	testCases := []struct {
		Input    string
		Expected *Predicate
	}{
		{
			Input: `resource(#ambient, $0)`,
			Expected: &Predicate{
				Name: "resource",
				IDs: []*Atom{
					{Symbol: sptr("ambient")},
					{Variable: ui32ptr(0)},
				},
			},
		},
		{
			Input: `resource(#ambient, $0, #read)`,
			Expected: &Predicate{
				Name: "resource",
				IDs: []*Atom{
					{Symbol: sptr("ambient")},
					{Variable: ui32ptr(0)},
					{Symbol: sptr("read")},
				},
			},
		},
		{
			Input: `right(#authority, "/a/file1.txt", #read)`,
			Expected: &Predicate{
				Name: "right",
				IDs: []*Atom{
					{Symbol: sptr("authority")},
					{String: sptr("/a/file1.txt")},
					{Symbol: sptr("read")},
				},
			},
		},
		{
			Input: `right("/a/file1.txt", #read)`,
			Expected: &Predicate{
				Name: "right",
				IDs: []*Atom{
					{String: sptr("/a/file1.txt")},
					{Symbol: sptr("read")},
				},
			},
		},
		{
			Input: `right("/a/file1.txt", $1)`,
			Expected: &Predicate{
				Name: "right",
				IDs: []*Atom{
					{String: sptr("/a/file1.txt")},
					{Variable: ui32ptr(1)},
				},
			},
		},
		{
			Input: `right($1, "hex:41414141")`,
			Expected: &Predicate{
				Name: "right",
				IDs: []*Atom{
					{Variable: ui32ptr(1)},
					{Bytes: hexsptr("41414141")},
				},
			},
		},
		{
			Input: `right($1, ["hex:41414141", #sym])`,
			Expected: &Predicate{
				Name: "right",
				IDs: []*Atom{
					{Variable: ui32ptr(1)},
					{Set: []*Atom{{Bytes: hexsptr("41414141")}, {Symbol: sptr("sym")}}},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed := &Predicate{}
			err := parser.ParseString(testCase.Input, parsed)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, parsed)
		})
	}
}

func TestGrammarConstraint(t *testing.T) {
	parser, err := participle.Build(&Constraint{}, defaultParserOptions...)
	require.NoError(t, err)

	testCases := []struct {
		Input    string
		Expected *Constraint
	}{
		{
			Input: `$0 == 1`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(0),
					Int: &IntComparison{
						Operation: sptr("=="),
						Target:    i64ptr(1),
					},
				},
			},
		},
		{
			Input: `$1 > 2`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(1),
					Int: &IntComparison{
						Operation: sptr(">"),
						Target:    i64ptr(2),
					},
				},
			},
		},
		{
			Input: `$0 >= 1`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(0),
					Int: &IntComparison{
						Operation: sptr(">="),
						Target:    i64ptr(1),
					},
				},
			},
		},
		{
			Input: `$0 < 1`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(0),
					Int: &IntComparison{
						Operation: sptr("<"),
						Target:    i64ptr(1),
					},
				},
			},
		},
		{
			Input: `$0 <= 1`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(0),
					Int: &IntComparison{
						Operation: sptr("<="),
						Target:    i64ptr(1),
					},
				},
			},
		},
		{
			Input: `$0 in [1, 2, 3]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(0),
					Set: &Set{
						Int: []int64{1, 2, 3},
						Not: false,
					},
				},
			},
		},
		{
			Input: `$0 not in [4,5,6]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(0),
					Set: &Set{
						Int: []int64{4, 5, 6},
						Not: true,
					},
				},
			},
		},
		{
			Input: `$0 == "abc"`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(0),
					String: &StringComparison{
						Operation: sptr("=="),
						Target:    sptr("abc"),
					},
				},
			},
		},
		{
			Input: `prefix($0, "abc")`,
			Expected: &Constraint{
				FunctionConstraint: &FunctionConstraint{
					Function: sptr("prefix"),
					Variable: ui32ptr(0),
					Argument: sptr("abc"),
				},
			},
		},
		{
			Input: `suffix($0, "abc")`,
			Expected: &Constraint{
				FunctionConstraint: &FunctionConstraint{
					Function: sptr("suffix"),
					Variable: ui32ptr(0),
					Argument: sptr("abc"),
				},
			},
		},
		{
			Input: `match($0, "^abc[a-z]+$") `,
			Expected: &Constraint{
				FunctionConstraint: &FunctionConstraint{
					Function: sptr("match"),
					Variable: ui32ptr(0),
					Argument: sptr("^abc[a-z]+$"),
				},
			},
		},
		{
			Input: `$0 in ["abc", "def"]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(0),
					Set: &Set{
						String: []string{"abc", "def"},
						Not:    false,
					},
				},
			},
		},
		{
			Input: `$0 not in ["abc", "def"]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(0),
					Set: &Set{
						String: []string{"abc", "def"},
						Not:    true,
					},
				},
			},
		},
		{
			Input: `$0 < "2006-01-02T15:04:05Z07:00"`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(0),
					Date: &DateComparison{
						Operation: sptr("<"),
						Target:    sptr("2006-01-02T15:04:05Z07:00"),
					},
				},
			},
		},
		{
			Input: `$0 > "2006-01-02T15:04:05Z07:00"`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(0),
					Date: &DateComparison{
						Operation: sptr(">"),
						Target:    sptr("2006-01-02T15:04:05Z07:00"),
					},
				},
			},
		},
		{
			Input: `$0 in [#a, #b, #c]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(0),
					Set: &Set{
						Symbols: []string{"a", "b", "c"},
						Not:     false,
					},
				},
			},
		},
		{
			Input: `$0 not in [#a, #b, #c]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(0),
					Set: &Set{
						Symbols: []string{"a", "b", "c"},
						Not:     true,
					},
				},
			},
		},
		{
			Input: `$0 in ["hex:41", "hex:42", "hex:43"]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(0),
					Set: &Set{
						Bytes: []HexString{"41", "42", "43"},
						Not:   false,
					},
				},
			},
		},
		{
			Input: `$0 not in ["hex:abcdef", "hex:01234", "hex:56789"]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: ui32ptr(0),
					Set: &Set{
						Bytes: []HexString{"abcdef", "01234", "56789"},
						Not:   true,
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed := &Constraint{}
			err := parser.ParseString(testCase.Input, parsed)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, parsed)
		})
	}

}

func TestGrammarRule(t *testing.T) {
	parser, err := participle.Build(&Rule{}, defaultParserOptions...)
	require.NoError(t, err)

	testCases := []struct {
		Input    string
		Expected *Rule
	}{
		{
			Input: `*grandparent(#a, #c) <- parent(#a, #b), parent(#b, #c)`,
			Expected: &Rule{
				Head: &Predicate{
					Name: "grandparent",
					IDs: []*Atom{
						{Symbol: sptr("a")},
						{Symbol: sptr("c")},
					},
				},
				Body: []*Predicate{
					{
						Name: "parent",
						IDs: []*Atom{
							{Symbol: sptr("a")},
							{Symbol: sptr("b")},
						},
					},
					{
						Name: "parent",
						IDs: []*Atom{
							{Symbol: sptr("b")},
							{Symbol: sptr("c")},
						},
					},
				},
			},
		},
		{
			Input: `*grandparent(#a, #c) <- parent(#a, #b), parent(#b, #c) @ $0 > 42, prefix($1, "test")`,
			Expected: &Rule{
				Head: &Predicate{
					Name: "grandparent",
					IDs: []*Atom{
						{Symbol: sptr("a")},
						{Symbol: sptr("c")},
					},
				},
				Body: []*Predicate{
					{
						Name: "parent",
						IDs: []*Atom{
							{Symbol: sptr("a")},
							{Symbol: sptr("b")},
						},
					},
					{
						Name: "parent",
						IDs: []*Atom{
							{Symbol: sptr("b")},
							{Symbol: sptr("c")},
						},
					},
				},
				Constraints: []*Constraint{
					{
						VariableConstraint: &VariableConstraint{
							Variable: ui32ptr(0),
							Int: &IntComparison{
								Operation: sptr(">"),
								Target:    i64ptr(42),
							},
						},
					},
					{
						FunctionConstraint: &FunctionConstraint{
							Function: sptr("prefix"),
							Variable: ui32ptr(1),
							Argument: sptr("test"),
						},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed := &Rule{}
			err := parser.ParseString(testCase.Input, parsed)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, parsed)
		})
	}
}

func sptr(s string) *string {
	return &s
}
func ui32ptr(i uint32) *uint32 {
	return &i
}
func i64ptr(i int64) *int64 {
	return &i
}

func hexsptr(s string) *HexString {
	h := HexString(s)
	return &h
}
