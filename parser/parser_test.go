package parser

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/datalog"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	Input         string
	Expected      interface{}
	ExpectFailure bool
	ExpectErr     error
}

func getFactTestCases() []testCase {
	return []testCase{
		{
			Input: `right(#authority, "/a/file1.txt", #read)`,
			Expected: biscuit.Fact{
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
			Input:         `right(#authority, "/a/file1.txt", $0)`,
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
}

func getRuleTestCases() []testCase {
	t1 := time.Now()
	t2 := time.Now().Add(2 * time.Second)

	return []testCase{
		{
			Input: `*grandparent(#a, #c) <- parent(#a, #b), parent(#b, #c) @ $0 > 42, prefix($1, "abc")`,
			Expected: biscuit.Rule{
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
			Input: `*grandparent(#a, #c) <- parent(#a, #b), parent(#b, #c)`,
			Expected: biscuit.Rule{
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
			Input: fmt.Sprintf(`*rule1(#a) <- body1(#b) @ $0 > "%s", $0 < "%s"`, t1.Format(time.RFC3339), t2.Format(time.RFC3339)),
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Atom{biscuit.Symbol("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Atom{biscuit.Symbol("b")},
				}},
				Constraints: []biscuit.Constraint{
					{
						Name: biscuit.Variable(0),
						Checker: biscuit.DateComparisonChecker{
							Comparison: datalog.DateComparisonAfter,
							Date:       biscuit.Date(time.Unix(t1.Unix(), 0)),
						},
					},
					{
						Name: biscuit.Variable(0),
						Checker: biscuit.DateComparisonChecker{
							Comparison: datalog.DateComparisonBefore,
							Date:       biscuit.Date(time.Unix(t2.Unix(), 0)),
						},
					},
				},
			},
		},
		{
			Input:         fmt.Sprintf(`*rule1(#a) <- body1(#b) @ $0 > "%s"`, t1.Format(time.RFC1123)),
			ExpectFailure: true,
		},
		{
			Input: `*rule1(#a) <- body1(#b) @ $0 > 0, $1 < 1, $2 >= 2, $3 <= 3, $4 == 4, $5 in [1, 2, 3], $6 not in [4,5,6]`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Atom{biscuit.Symbol("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Atom{biscuit.Symbol("b")},
				}},
				Constraints: []biscuit.Constraint{
					{
						Name: biscuit.Variable(0),
						Checker: biscuit.IntegerComparisonChecker{
							Comparison: datalog.IntegerComparisonGT,
							Integer:    0,
						},
					},
					{
						Name: biscuit.Variable(1),
						Checker: biscuit.IntegerComparisonChecker{
							Comparison: datalog.IntegerComparisonLT,
							Integer:    1,
						},
					},
					{
						Name: biscuit.Variable(2),
						Checker: biscuit.IntegerComparisonChecker{
							Comparison: datalog.IntegerComparisonGTE,
							Integer:    2,
						},
					},
					{
						Name: biscuit.Variable(3),
						Checker: biscuit.IntegerComparisonChecker{
							Comparison: datalog.IntegerComparisonLTE,
							Integer:    3,
						},
					},
					{
						Name: biscuit.Variable(4),
						Checker: biscuit.IntegerComparisonChecker{
							Comparison: datalog.IntegerComparisonEqual,
							Integer:    4,
						},
					},
					{
						Name: biscuit.Variable(5),
						Checker: biscuit.IntegerInChecker{
							Set: map[biscuit.Integer]struct{}{1: {}, 2: {}, 3: {}},
							Not: false,
						},
					},
					{
						Name: biscuit.Variable(6),
						Checker: biscuit.IntegerInChecker{
							Set: map[biscuit.Integer]struct{}{4: {}, 5: {}, 6: {}},
							Not: true,
						},
					},
				},
			},
		},
		{
			Input: `*rule1(#a) <- body1(#b) @ $0 == "abc", prefix($1, "def"), suffix($2, "ghi"), match($3, "file[0-9]+.txt"), $4 in ["a","b"], $5 not in ["c", "d"]`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Atom{biscuit.Symbol("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Atom{biscuit.Symbol("b")},
				}},
				Constraints: []biscuit.Constraint{
					{
						Name: biscuit.Variable(0),
						Checker: biscuit.StringComparisonChecker{
							Comparison: datalog.StringComparisonEqual,
							Str:        "abc",
						},
					},
					{
						Name: biscuit.Variable(1),
						Checker: biscuit.StringComparisonChecker{
							Comparison: datalog.StringComparisonPrefix,
							Str:        "def",
						},
					},
					{
						Name: biscuit.Variable(2),
						Checker: biscuit.StringComparisonChecker{
							Comparison: datalog.StringComparisonSuffix,
							Str:        "ghi",
						},
					},
					{
						Name:    biscuit.Variable(3),
						Checker: biscuit.StringRegexpChecker(*regexp.MustCompile(`file[0-9]+.txt`)),
					},
					{
						Name: biscuit.Variable(4),
						Checker: biscuit.StringInChecker{
							Set: map[biscuit.String]struct{}{"a": {}, "b": {}},
							Not: false,
						},
					},
					{
						Name: biscuit.Variable(5),
						Checker: biscuit.StringInChecker{
							Set: map[biscuit.String]struct{}{"c": {}, "d": {}},
							Not: true,
						},
					},
				},
			},
		},
		{
			Input: `*rule1(#a) <- body1(#b) @ $0 in [#a, #b], $1 not in [#c, #d]`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Atom{biscuit.Symbol("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Atom{biscuit.Symbol("b")},
				}},
				Constraints: []biscuit.Constraint{
					{
						Name: biscuit.Variable(0),
						Checker: biscuit.SymbolInChecker{
							Set: map[biscuit.Symbol]struct{}{"a": {}, "b": {}},
							Not: false,
						},
					},
					{
						Name: biscuit.Variable(1),
						Checker: biscuit.SymbolInChecker{
							Set: map[biscuit.Symbol]struct{}{"c": {}, "d": {}},
							Not: true,
						},
					},
				},
			},
		},

		{
			Input:         `*grandparent(#a, #c) <-- parent(#a, #b), parent(#b, #c)`,
			ExpectFailure: true,
		},
		{
			Input:         `<- parent(#a, #b), parent(#b, #c)`,
			ExpectFailure: true,
		},
	}
}

func getCaveatTestCases() []testCase {
	return []testCase{
		{
			Input: `[ *caveat0($0) <- parent(#a, #b), parent(#b, #c) @ $0 in [1,2,3] || *caveat1() <- right(#read, "/a/file1.txt") ]`,
			Expected: biscuit.Caveat{
				Queries: []biscuit.Rule{
					{
						Head: biscuit.Predicate{
							Name: "caveat0",
							IDs:  []biscuit.Atom{biscuit.Variable(0)},
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
								Checker: biscuit.IntegerInChecker{
									Set: map[biscuit.Integer]struct{}{1: {}, 2: {}, 3: {}},
								},
							},
						},
					},
					{
						Head: biscuit.Predicate{
							Name: "caveat1",
						},
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
			Input:         `[ *caveat1($0) <- parent(#a, #b), parent(#b, #c) @ $0 in [1,2,3]`,
			ExpectFailure: true,
		},
	}
}

func TestParserFact(t *testing.T) {
	p := New()
	for _, testCase := range getFactTestCases() {
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
	p := New()
	for _, testCase := range getRuleTestCases() {
		t.Run(testCase.Input, func(t *testing.T) {
			rule, err := p.Rule(testCase.Input)
			if testCase.ExpectFailure {
				if testCase.ExpectErr != nil {
					require.Equal(t, testCase.ExpectErr, err)
				} else {
					require.Error(t, err)
				}
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.Expected, rule)
			}
		})
	}
}

func TestParserCaveat(t *testing.T) {
	p := New()
	for _, testCase := range getCaveatTestCases() {
		t.Run(testCase.Input, func(t *testing.T) {
			caveat, err := p.Caveat(testCase.Input)
			if testCase.ExpectFailure {
				if testCase.ExpectErr != nil {
					require.Equal(t, testCase.ExpectErr, err)
				} else {
					require.Error(t, err)
				}
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.Expected, caveat)
			}
		})
	}
}

func TestMustParserFact(t *testing.T) {
	p := New()
	for _, testCase := range getFactTestCases() {
		t.Run(testCase.Input, func(t *testing.T) {
			if testCase.ExpectFailure {
				defer func() {
					r := recover()
					require.NotNil(t, r)
				}()
			}

			fact := p.Must().Fact(testCase.Input)
			require.Equal(t, testCase.Expected, fact)
		})
	}
}

func TestMustParseRule(t *testing.T) {
	p := New()
	for _, testCase := range getRuleTestCases() {
		t.Run(testCase.Input, func(t *testing.T) {
			if testCase.ExpectFailure {
				defer func() {
					r := recover()
					require.NotNil(t, r)
				}()
			}
			rule := p.Must().Rule(testCase.Input)
			require.Equal(t, testCase.Expected, rule)
		})
	}
}

func TestMustParserCaveat(t *testing.T) {
	p := New()
	for _, testCase := range getCaveatTestCases() {
		t.Run(testCase.Input, func(t *testing.T) {
			if testCase.ExpectFailure {
				defer func() {
					r := recover()
					require.NotNil(t, r)
				}()
			}

			caveat := p.Must().Caveat(testCase.Input)
			require.Equal(t, testCase.Expected, caveat)
		})
	}
}
