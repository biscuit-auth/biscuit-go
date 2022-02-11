package parser

import (
	"fmt"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go"
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
			Input: `right("/a/file1.txt", "read", ["read", "/a/file2.txt"])`,
			Expected: biscuit.Fact{
				Predicate: biscuit.Predicate{
					Name: "right",
					IDs: []biscuit.Term{
						biscuit.String("/a/file1.txt"),
						biscuit.String("read"),
						biscuit.Set{
							biscuit.String("read"),
							biscuit.String("/a/file2.txt"),
						},
					},
				},
			},
		},
		{
			Input:         `right("/a/file1.txt", $0)`,
			ExpectFailure: true,
			ExpectErr:     ErrVariableInFact,
		},
		{
			Input:         `right("/a/file1.txt"`,
			ExpectFailure: true,
		},
		{
			Input:         `right(/a/file1.txt")`,
			ExpectFailure: true,
		},
		{
			Input:         `right("/a/file1.txt", [$0])`,
			ExpectFailure: true,
		},
	}
}

func getRuleTestCases() []testCase {
	t1, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	t2, _ := time.Parse(time.RFC3339, time.Now().Add(2*time.Second).Format(time.RFC3339))

	return []testCase{
		{
			Input: `grandparent("a", "c") <- parent("a", "b"), parent("b", "c"), $0 > 42, $1.starts_with("abc")`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "grandparent",
					IDs: []biscuit.Term{
						biscuit.String("a"),
						biscuit.String("c"),
					},
				},
				Body: []biscuit.Predicate{
					{
						Name: "parent",
						IDs: []biscuit.Term{
							biscuit.String("a"),
							biscuit.String("b"),
						},
					},
					{
						Name: "parent",
						IDs: []biscuit.Term{
							biscuit.String("b"),
							biscuit.String("c"),
						},
					},
				},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.Integer(42)},
						biscuit.BinaryGreaterThan,
					},
					{
						biscuit.Value{Term: biscuit.Variable("1")},
						biscuit.Value{Term: biscuit.String("abc")},
						biscuit.BinaryPrefix,
					},
				},
			},
		},
		{
			Input: `grandparent("a", "c") <- parent("a", "b"), parent("b", "c")`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "grandparent",
					IDs: []biscuit.Term{
						biscuit.String("a"),
						biscuit.String("c"),
					},
				},
				Body: []biscuit.Predicate{
					{
						Name: "parent",
						IDs: []biscuit.Term{
							biscuit.String("a"),
							biscuit.String("b"),
						},
					},
					{
						Name: "parent",
						IDs: []biscuit.Term{
							biscuit.String("b"),
							biscuit.String("c"),
						},
					},
				},
				Expressions: []biscuit.Expression{},
			},
		},
		{
			Input: fmt.Sprintf(`rule1("a") <- body1("b"), $0 > %s, $0 < %s`, t1.Format(time.RFC3339), t2.Format(time.RFC3339)),

			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.String("b")},
				}},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.Date(t1)},
						biscuit.BinaryGreaterThan,
					},
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.Date(t2)},
						biscuit.BinaryLessThan,
					},
				},
			},
		},
		/*{
			Input:         fmt.Sprintf(`rule1("a") <- body1("b"), $0 > %s`, t1.Format(time.RFC1123)),
			ExpectFailure: true,
		},
		{
			Input: `rule1("a") <- body1("b"), $0 > 0, $1 < 1, $2 >= 2, $3 <= 3, $4 == 4, [1, 2, 3].contains($5), $6 not in [4,5,6]`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.String("b")},
				}},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.Integer(0)},
						biscuit.BinaryGreaterThan,
					},
					{
						biscuit.Value{Term: biscuit.Variable("1")},
						biscuit.Value{Term: biscuit.Integer(1)},
						biscuit.BinaryLessThan,
					},
					{
						biscuit.Value{Term: biscuit.Variable("2")},
						biscuit.Value{Term: biscuit.Integer(2)},
						biscuit.BinaryGreaterOrEqual,
					},
					{
						biscuit.Value{Term: biscuit.Variable("3")},
						biscuit.Value{Term: biscuit.Integer(3)},
						biscuit.BinaryLessOrEqual,
					},
					{
						biscuit.Value{Term: biscuit.Variable("04")},
						biscuit.Value{Term: biscuit.Integer(4)},
						biscuit.BinaryEqual,
					},
					{
						biscuit.Value{Term: biscuit.Set{biscuit.Integer(1), biscuit.Integer(2), biscuit.Integer(3)}},
						biscuit.Value{Term: biscuit.Variable("5")},
						biscuit.BinaryContains,
					},
					{
						biscuit.Value{Term: biscuit.Set{biscuit.Integer(4), biscuit.Integer(5), biscuit.Integer(6)}},
						biscuit.Value{Term: biscuit.Variable("6")},
						biscuit.BinaryContains,
						biscuit.UnaryNegate,
					},
				},
			},
		},
			{
				Input: `rule1(#a) <- body1(#b) @ $0 == "abc", prefix($1, "def"), suffix($2, "ghi"), match($3, "file[0-9]+.txt"), $4 in ["a","b"], $5 not in ["c", "d"]`,
				Expected: biscuit.Rule{
					Head: biscuit.Predicate{
						Name: "rule1",
						IDs:  []biscuit.Term{biscuit.String("a")},
					},
					Body: []biscuit.Predicate{{
						Name: "body1",
						IDs:  []biscuit.Term{biscuit.String("b")},
					}},
					Constraints: []biscuit.Constraint{
						{
							Name: biscuit.Variable("0"),
							Checker: biscuit.StringComparisonChecker{
								Comparison: datalog.StringComparisonEqual,
								Str:        "abc",
							},
						},
						{
							Name: biscuit.Variable("1"),
							Checker: biscuit.StringComparisonChecker{
								Comparison: datalog.StringComparisonPrefix,
								Str:        "def",
							},
						},
						{
							Name: biscuit.Variable("2"),
							Checker: biscuit.StringComparisonChecker{
								Comparison: datalog.StringComparisonSuffix,
								Str:        "ghi",
							},
						},
						{
							Name:    biscuit.Variable("3"),
							Checker: biscuit.StringRegexpChecker(*regexp.MustCompile(`file[0-9]+.txt`)),
						},
						{
							Name: biscuit.Variable("4"),
							Checker: biscuit.StringInChecker{
								Set: map[biscuit.String]struct{}{"a": {}, "b": {}},
								Not: false,
							},
						},
						{
							Name: biscuit.Variable("5"),
							Checker: biscuit.StringInChecker{
								Set: map[biscuit.String]struct{}{"c": {}, "d": {}},
								Not: true,
							},
						},
					},
				},
			},
			{
				Input: `rule1(#a) <- body1(#b) @ $0 in [#a, #b], $1 not in [#c, #d]`,
				Expected: biscuit.Rule{
					Head: biscuit.Predicate{
						Name: "rule1",
						IDs:  []biscuit.Term{biscuit.String("a")},
					},
					Body: []biscuit.Predicate{{
						Name: "body1",
						IDs:  []biscuit.Term{biscuit.String("b")},
					}},
					Constraints: []biscuit.Constraint{
						{
							Name: biscuit.Variable("0"),
							Checker: biscuit.StringInChecker{
								Set: map[biscuit.String]struct{}{"a": {}, "b": {}},
								Not: false,
							},
						},
						{
							Name: biscuit.Variable("1"),
							Checker: biscuit.StringInChecker{
								Set: map[biscuit.String]struct{}{"c": {}, "d": {}},
								Not: true,
							},
						},
					},
				},
			},
			{
				Input: `rule1(#a) <- body1("hex:41414141") @ $0 in ["hex:41414141", "hex:42424242"], $1 not in ["hex:0000" "hex:ffff"]`,
				Expected: biscuit.Rule{
					Head: biscuit.Predicate{
						Name: "rule1",
						IDs:  []biscuit.Term{biscuit.String("a")},
					},
					Body: []biscuit.Predicate{{
						Name: "body1",
						IDs:  []biscuit.Term{biscuit.Bytes([]byte{0x41, 0x41, 0x41, 0x41})},
					}},
					Constraints: []biscuit.Constraint{
						{
							Name: biscuit.Variable("0"),
							Checker: biscuit.BytesInChecker{
								Set: map[string]struct{}{"AAAA": {}, "BBBB": {}},
								Not: false,
							},
						},
						{
							Name: biscuit.Variable("1"),
							Checker: biscuit.BytesInChecker{
								Set: map[string]struct{}{string([]byte{0x00, 0x00}): {}, string([]byte{0xFF, 0xFF}): {}},
								Not: true,
							},
						},
					},
				},
			},
			{
				Input: `rule1(#a) <- body1("hex:41414141") @ $0 == "hex:41414141"`,
				Expected: biscuit.Rule{
					Head: biscuit.Predicate{
						Name: "rule1",
						IDs:  []biscuit.Term{biscuit.String("a")},
					},
					Body: []biscuit.Predicate{{
						Name: "body1",
						IDs:  []biscuit.Term{biscuit.Bytes([]byte{0x41, 0x41, 0x41, 0x41})},
					}},
					Constraints: []biscuit.Constraint{
						{
							Name: biscuit.Variable("0"),
							Checker: biscuit.BytesComparisonChecker{
								Comparison: datalog.BytesComparisonEqual,
								Bytes:      []byte("AAAA"),
							},
						},
					},
				},
			},
			{
				Input: `rule1(#a) <- body1($0, $1) @ $0 in ["abc", "def"], $1 not in [41, 42]`,
				Expected: biscuit.Rule{
					Head: biscuit.Predicate{
						Name: "rule1",
						IDs:  []biscuit.Term{biscuit.String("a")},
					},
					Body: []biscuit.Predicate{{
						Name: "body1",
						IDs:  []biscuit.Term{biscuit.Variable("0"), biscuit.Variable("1")},
					}},
					Constraints: []biscuit.Constraint{
						{
							Name: biscuit.Variable("0"),
							Checker: biscuit.StringInChecker{
								Set: map[biscuit.String]struct{}{biscuit.String("abc"): {}, biscuit.String("def"): {}},
								Not: false,
							},
						},
						{
							Name: biscuit.Variable("1"),
							Checker: biscuit.IntegerInChecker{
								Set: map[biscuit.Integer]struct{}{biscuit.Integer(41): {}, biscuit.Integer(42): {}},
								Not: true,
							},
						},
					},
				},
			},*/

		{
			Input: `empty() <- body1($0, $1)`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "empty",
					IDs:  []biscuit.Term{},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.Variable("0"), biscuit.Variable("1")},
				}},
				Expressions: []biscuit.Expression{},
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
		{
			Input:         `rule1(#a) <- body1($0, $1), $0 in [$1, "foo"]`,
			ExpectFailure: true,
		},
	}
}

/*
func getCaveatTestCases() []testCase {
	return []testCase{
		{
			Input: `[ caveat0($0) <- parent(#a, #b), parent(#b, #c) @ $0 in [1,2,3] || caveat1() <- right(#read, "/a/file1.txt") ]`,
			Expected: biscuit.Check{
				Queries: []biscuit.Rule{
					{
						Head: biscuit.Predicate{
							Name: "caveat0",
							IDs:  []biscuit.Term{biscuit.Variable("0")},
						},
						Body: []biscuit.Predicate{
							{
								Name: "parent",
								IDs: []biscuit.Term{
									biscuit.String("a"),
									biscuit.String("b"),
								},
							},
							{
								Name: "parent",
								IDs: []biscuit.Term{
									biscuit.String("b"),
									biscuit.String("c"),
								},
							},
						},
						Constraints: []biscuit.Constraint{
							{
								Name: biscuit.Variable("0"),
								Checker: biscuit.IntegerInChecker{
									Set: map[biscuit.Integer]struct{}{1: {}, 2: {}, 3: {}},
								},
							},
						},
					},
					{
						Head: biscuit.Predicate{
							Name: "caveat1",
							IDs:  []biscuit.Term{},
						},
						Body: []biscuit.Predicate{
							{
								Name: "right",
								IDs: []biscuit.Term{
									biscuit.String("read"),
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
			Input:         `[ caveat1($0) <- parent(#a, #b), parent(#b, #c) @ $0 in [1,2,3]`,
			ExpectFailure: true,
		},
	}
}*/

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

// func TestParserCaveat(t *testing.T) {
// 	p := New()
// 	for _, testCase := range getCaveatTestCases() {
// 		t.Run(testCase.Input, func(t *testing.T) {
// 			caveat, err := p.Caveat(testCase.Input)
// 			if testCase.ExpectFailure {
// 				if testCase.ExpectErr != nil {
// 					require.Equal(t, testCase.ExpectErr, err)
// 				} else {
// 					require.Error(t, err)
// 				}
// 			} else {
// 				require.NoError(t, err)
// 				require.Equal(t, testCase.Expected, caveat)
// 			}
// 		})
// 	}
// }

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

// func TestMustParseRule(t *testing.T) {
// 	p := New()
// 	for _, testCase := range getRuleTestCases() {
// 		t.Run(testCase.Input, func(t *testing.T) {
// 			if testCase.ExpectFailure {
// 				defer func() {
// 					r := recover()
// 					require.NotNil(t, r)
// 				}()
// 			}
// 			rule := p.Must().Rule(testCase.Input)
// 			require.Equal(t, testCase.Expected, rule)
// 		})
// 	}
// }

// func TestMustParserCaveat(t *testing.T) {
// 	p := New()
// 	for _, testCase := range getCaveatTestCases() {
// 		t.Run(testCase.Input, func(t *testing.T) {
// 			if testCase.ExpectFailure {
// 				defer func() {
// 					r := recover()
// 					require.NotNil(t, r)
// 				}()
// 			}

// 			caveat := p.Must().Caveat(testCase.Input)
// 			require.Equal(t, testCase.Expected, caveat)
// 		})
// 	}
// }
