package parser

import (
	"testing"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/datalog"
	"github.com/stretchr/testify/require"
)

func TestParserFact(t *testing.T) {
	testCases := []struct {
		Input         string
		Expected      *biscuit.Fact
		ExpectFailure bool
		ExpectErr     error
	}{
		{
			Input: `right(#authority, "/a/file1.txt", #read)`,
			Expected: &biscuit.Fact{
				Predicate: biscuit.Predicate{
					Name: "right",
					IDs: []biscuit.Atom{
						biscuit.Symbol("authority"),
						biscuit.String("/a/file1.txt"),
						biscuit.Symbol("read"),
					},
				},
			},
		},
		{
			Input:         `right(#authority, "/a/file1.txt", 0?)`,
			ExpectFailure: true,
			ExpectErr:     ErrVariableInFact,
		},
		{
			Input:         `right(#authority, "/a/file1.txt"`,
			ExpectFailure: true,
		},
		{
			Input:         `right(#authority, /a/file1.txt")`,
			ExpectFailure: true,
		},
	}

	p := New()
	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			fact, err := p.Fact(testCase.Input)
			if testCase.ExpectFailure {
				if testCase.ExpectErr != nil {
					require.Equal(t, testCase.ExpectErr, err)
				} else {
					require.Error(t, err)
				}
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.Expected, fact)
			}
		})
	}
}

func TestParseRule(t *testing.T) {
	testCases := []struct {
		Input         string
		Expected      *biscuit.Rule
		ExpectFailure bool
		ExpectErr     error
	}{
		{
			Input: `grandparent(#a, #c) <- parent(#a, #b), parent(#b, #c), 0? > 42, prefix(1?, "abc")`,
			Expected: &biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "grandparent",
					IDs: []biscuit.Atom{
						biscuit.Symbol("a"),
						biscuit.Symbol("c"),
					},
				},
				Body: []biscuit.Predicate{
					{
						Name: "parent",
						IDs: []biscuit.Atom{
							biscuit.Symbol("a"),
							biscuit.Symbol("b"),
						},
					},
					{
						Name: "parent",
						IDs: []biscuit.Atom{
							biscuit.Symbol("b"),
							biscuit.Symbol("c"),
						},
					},
				},
				Constraints: []biscuit.Constraint{
					{
						Name: biscuit.Variable(0),
						Checker: biscuit.IntegerComparisonChecker{
							Comparison: datalog.IntegerComparisonGT,
							Integer:    42,
						},
					},
					{
						Name: biscuit.Variable(1),
						Checker: biscuit.StringComparisonChecker{
							Comparison: datalog.StringComparisonPrefix,
							Str:        "abc",
						},
					},
				},
			},
		},
		{
			Input: `grandparent(#a, #c) <- parent(#a, #b), parent(#b, #c)`,
			Expected: &biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "grandparent",
					IDs: []biscuit.Atom{
						biscuit.Symbol("a"),
						biscuit.Symbol("c"),
					},
				},
				Body: []biscuit.Predicate{
					{
						Name: "parent",
						IDs: []biscuit.Atom{
							biscuit.Symbol("a"),
							biscuit.Symbol("b"),
						},
					},
					{
						Name: "parent",
						IDs: []biscuit.Atom{
							biscuit.Symbol("b"),
							biscuit.Symbol("c"),
						},
					},
				},
				Constraints: []biscuit.Constraint{},
			},
		},
		{
			Input:         `grandparent(#a, #c) <-- parent(#a, #b), parent(#b, #c)`,
			ExpectFailure: true,
		},
		{
			Input:         `<- parent(#a, #b), parent(#b, #c)`,
			ExpectFailure: true,
		},
	}

	p := New()
	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			fact, err := p.Rule(testCase.Input)
			if testCase.ExpectFailure {
				if testCase.ExpectErr != nil {
					require.Equal(t, testCase.ExpectErr, err)
				} else {
					require.Error(t, err)
				}
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.Expected, fact)
			}
		})
	}
}

func TestParserCaveat(t *testing.T) {
	testCases := []struct {
		Input         string
		Expected      *biscuit.Caveat
		ExpectFailure bool
		ExpectErr     error
	}{
		{
			Input: `[ ?- parent(#a, #b), parent(#b, #c), 0? in [1,2,3], ?- right(#read, "/a/file1.txt") ]`,
			Expected: &biscuit.Caveat{
				Queries: []biscuit.Rule{
					{
						Body: []biscuit.Predicate{
							{
								Name: "parent",
								IDs: []biscuit.Atom{
									biscuit.Symbol("a"),
									biscuit.Symbol("b"),
								},
							},
							{
								Name: "parent",
								IDs: []biscuit.Atom{
									biscuit.Symbol("b"),
									biscuit.Symbol("c"),
								},
							},
						},
						Constraints: []biscuit.Constraint{
							{
								Name: biscuit.Variable(0),
								Checker: biscuit.IntegerInChecker{
									Set: map[biscuit.Integer]struct{}{1: {}, 2: {}, 3: {}},
								},
							},
						},
					},
					{
						Body: []biscuit.Predicate{
							{
								Name: "right",
								IDs: []biscuit.Atom{
									biscuit.Symbol("read"),
									biscuit.String("/a/file1.txt"),
								},
							},
						},
						Constraints: []biscuit.Constraint{},
					},
				},
			},
		},
		{
			Input:         `[ ?- parent(#a, #b), parent(#b, #c), 0? in [1,2,3]`,
			ExpectFailure: true,
		},
	}

	p := New()
	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			fact, err := p.Caveat(testCase.Input)
			if testCase.ExpectFailure {
				if testCase.ExpectErr != nil {
					require.Equal(t, testCase.ExpectErr, err)
				} else {
					require.Error(t, err)
				}
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.Expected, fact)
			}
		})
	}
}
