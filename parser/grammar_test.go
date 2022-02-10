package parser

import (
	"testing"

	"github.com/alecthomas/participle/v2"
	"github.com/biscuit-auth/biscuit-go"
	"github.com/stretchr/testify/require"
)

func TestGrammarPredicate(t *testing.T) {
	parser, err := participle.Build(&Predicate{}, DefaultParserOptions...)
	require.NoError(t, err)

	testCases := []struct {
		Input    string
		Expected *Predicate
	}{
		{
			Input: `resource($var1)`,
			Expected: &Predicate{
				Name: sptr("resource"),
				IDs: []*Term{
					{Variable: varptr("var1")},
				},
			},
		},
		{
			Input: `resource($0, "read")`,
			Expected: &Predicate{
				Name: sptr("resource"),
				IDs: []*Term{
					{Variable: varptr("0")},
					{String: sptr("read")},
				},
			},
		},
		{
			Input: `right("/a/file1.txt", "read")`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{String: sptr("/a/file1.txt")},
					{String: sptr("read")},
				},
			},
		},
		{
			Input: `right("/a/file1.txt", "read")`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{String: sptr("/a/file1.txt")},
					{String: sptr("read")},
				},
			},
		},
		{
			Input: `right("/a/file1.txt", $1)`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{String: sptr("/a/file1.txt")},
					{Variable: varptr("1")},
				},
			},
		},
		{
			Input: `right($1, "hex:41414141")`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{Variable: varptr("1")},
					{Bytes: hexsptr("41414141")},
				},
			},
		},
		{
			Input: `right($1, ["hex:41414141", "sym"])`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{Variable: varptr("1")},
					{Set: []*Term{{Bytes: hexsptr("41414141")}, {String: sptr("sym")}}},
				},
			},
		},
		{
			Input: `right($1, true, false)`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{Variable: varptr("1")},
					{Bool: boolptr(true)},
					{Bool: boolptr(false)},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed := &Predicate{}
			err := parser.ParseString("test", testCase.Input, parsed)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, parsed)
		})
	}
}

func TestGrammarExpression(t *testing.T) {
	parser, err := participle.Build(&Expression{}, DefaultParserOptions...)
	require.NoError(t, err)

	testCases := []struct {
		Input    string
		Expected *biscuit.Expression
	}{
		{
			Input: `$0 == 1`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.Integer(1)},
				biscuit.BinaryEqual,
			},
		},
		{
			Input: `$1 > 2`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("1")},
				biscuit.Value{Term: biscuit.Integer(2)},
				biscuit.BinaryGreaterThan,
			},
		},
		{
			Input: `$0 >= 1`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.Integer(1)},
				biscuit.BinaryGreaterOrEqual,
			},
		},
		{
			Input: `$0 < 1`,
			Expected: &biscuit.Expression{
				biscuit.Value{biscuit.Variable("0")},
				biscuit.Value{biscuit.Integer(1)},
				biscuit.BinaryLessThan,
			},
		},
		{
			Input: `$0 <= 1`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.Integer(1)},
				biscuit.BinaryLessOrEqual,
			},
		},
		{
			Input: `[1, 2, 3].contains($0)`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Set{biscuit.Integer(1), biscuit.Integer(2), biscuit.Integer(3)}},
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.BinaryContains,
			},
		},
		/*{
			Input: `$0 not in [4,5,6]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Set: &Set{
						Int: []int64{4, 5, 6},
						Not: true,
					},
				},
			},
		},*/
		{
			Input: `$0 == "abc"`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.String("abc")},
				biscuit.BinaryEqual,
			},
		},
		{
			Input: `$0.starts_with("abc")`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.String("abc")},
				biscuit.BinaryPrefix,
			},
		},
		{
			Input: `$0.ends_with("abc")`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.String("abc")},
				biscuit.BinarySuffix,
			},
		},
		/*{
			Input: `$0.matches("^abc[a-z]+$") `,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.String("^abc[a-z]+$")},
				biscuit.BinaryRegex,
			},
		},*/
		{
			Input: `["abc", "def"].contains($0)`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Set{biscuit.String("abc"), biscuit.String("def")}},
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.BinaryContains,
			},
		},
		/*{
			Input: `$0 not in ["abc", "def"]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Set: &Set{
						String: []string{"abc", "def"},
						Not:    true,
					},
				},
			},
		},
		{
			Input: `$0 <= "2006-01-02T15:04:05Z07:00"`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Date: &DateComparison{
						Operation: sptr("<="),
						Target:    sptr("2006-01-02T15:04:05Z07:00"),
					},
				},
			},
		},
		{
			Input: `$0 >= "2006-01-02T15:04:05Z07:00"`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Date: &DateComparison{
						Operation: sptr(">="),
						Target:    sptr("2006-01-02T15:04:05Z07:00"),
					},
				},
			},
		},*/
		{
			Input: `["hex:41", "hex:42", "hex:43"].contains($0)`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Set{biscuit.Bytes([]byte("A")),
					biscuit.Bytes([]byte("B")), biscuit.Bytes([]byte("C"))}},
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.BinaryContains,
			},
		},
		/*{
			Input: `$0 not in ["hex:abcdef", "hex:01234", "hex:56789"]`,
			Expected: &Constraint{
				VariableConstraint: &VariableConstraint{
					Variable: varptr("0"),
					Set: &Set{
						Bytes: []HexString{"abcdef", "01234", "56789"},
						Not:   true,
					},
				},
			},
		},*/
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed := &Expression{}
			err := parser.ParseString("test", testCase.Input, parsed)
			require.NoError(t, err)

			var expr biscuit.Expression
			(*parsed).ToExpr(&expr)
			require.Equal(t, testCase.Expected, &expr)
		})
	}

}

func TestGrammarCheck(t *testing.T) {
	parser, err := participle.Build(&Check{}, DefaultParserOptions...)
	require.NoError(t, err)

	testCases := []struct {
		Input    string
		Expected *Check
	}{
		/*{
			Input: `check if grandparent("a", "c") <- parent("a", "b"), parent("b", "c")`,
			Expected: &Check{
				Queries: []*Rule{
					{
						Head: &Predicate{
							Name: sptr("grandparent"),
							IDs: []*Term{
								{String: sptr("a")},
								{String: sptr("c")},
							},
						},
						Body: []*RuleElement{
							{
								Predicate: &Predicate{

									Name: sptr("parent"),
									IDs: []*Term{
										{String: sptr("a")},
										{String: sptr("b")},
									},
								},
							},
							{
								Predicate: &Predicate{

									Name: sptr("parent"),
									IDs: []*Term{
										{String: sptr("b")},
										{String: sptr("c")},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Input: `[empty() <- parent("a", "b"), parent("b", "c")]`,
			Expected: &Check{[]*Rule{
				{
					Head: &Predicate{
						Name: sptr("empty"),
						IDs:  nil,
					},
					Body: []*Predicate{
						{
							Name: sptr("parent"),
							IDs: []*Term{
								{String: sptr("a")},
								{String: sptr("b")},
							},
						},
						{
							Name: sptr("parent"),
							IDs: []*Term{
								{String: sptr("b")},
								{String: sptr("c")},
							},
						},
					},
				},
			}},
		},
		{
			Input: `[grandparent("a", "c") <- parent("a", "b"), parent("b", "c") || grandparent("a", "c") <- parent("a", "b"), parent("b", "c") @ $0 > 42, prefix($1, "test")]`,
			Expected: &Check{[]*Rule{
				{
					Head: &Predicate{
						Name: sptr("grandparent"),
						IDs: []*Term{
							{String: sptr("a")},
							{String: sptr("c")},
						},
					},
					Body: []*Predicate{
						{
							Name: sptr("parent"),
							IDs: []*Term{
								{String: sptr("a")},
								{String: sptr("b")},
							},
						},
						{
							Name: sptr("parent"),
							IDs: []*Term{
								{String: sptr("b")},
								{String: sptr("c")},
							},
						},
					},
				},
				{
					Head: &Predicate{
						Name: sptr("grandparent"),
						IDs: []*Term{
							{String: sptr("a")},
							{String: sptr("c")},
						},
					},
					Body: []*Predicate{
						{
							Name: sptr("parent"),
							IDs: []*Term{
								{String: sptr("a")},
								{String: sptr("b")},
							},
						},
						{
							Name: sptr("parent"),
							IDs: []*Term{
								{String: sptr("b")},
								{String: sptr("c")},
							},
						},
					},
					Constraints: []*Constraint{
						{
							VariableConstraint: &VariableConstraint{
								Variable: varptr("0"),
								Int: &IntComparison{
									Operation: sptr(">"),
									Target:    i64ptr(42),
								},
							},
						},
						{
							FunctionConstraint: &FunctionConstraint{
								Function: sptr("prefix"),
								Variable: varptr("1"),
								Argument: sptr("test"),
							},
						},
					},
				},
			}},
		},*/
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed := &Check{}
			err := parser.ParseString("test", testCase.Input, parsed)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, parsed)
		})
	}
}

func TestGrammarRule(t *testing.T) {
	parser, err := participle.Build(&Rule{}, DefaultParserOptions...)
	require.NoError(t, err)

	testCases := []struct {
		Input    string
		Expected *Rule
	}{
		{
			Input: `// some comment
	grandparent("a", "c") <- parent("a", "b"), parent("b", "c")`,
			Expected: &Rule{
				Comments: []*Comment{commentptr("some comment")},
				Head: &Predicate{
					Name: sptr("grandparent"),
					IDs: []*Term{
						{String: sptr("a")},
						{String: sptr("c")},
					},
				},
				Body: []*RuleElement{
					{
						Predicate: &Predicate{
							Name: sptr("parent"),
							IDs: []*Term{
								{String: sptr("a")},
								{String: sptr("b")},
							},
						},
					},
					{
						Predicate: &Predicate{
							Name: sptr("parent"),
							IDs: []*Term{
								{String: sptr("b")},
								{String: sptr("c")},
							},
						},
					},
				},
			},
		},
		{
			Input: `empty() <- parent("a", "b"), parent("b", "c")`,
			Expected: &Rule{
				Head: &Predicate{
					Name: sptr("empty"),
				},
				Body: []*RuleElement{
					{
						Predicate: &Predicate{
							Name: sptr("parent"),
							IDs: []*Term{
								{String: sptr("a")},
								{String: sptr("b")},
							},
						},
					},
					{
						Predicate: &Predicate{
							Name: sptr("parent"),
							IDs: []*Term{
								{String: sptr("b")},
								{String: sptr("c")},
							},
						},
					},
				},
			},
		},
		{
			Input: `grandparent("a", "c") <- parent("a", "b"), parent("b", "c"), $0 > 42, $1.starts_with("test")`,
			Expected: &Rule{
				Head: &Predicate{
					Name: sptr("grandparent"),
					IDs: []*Term{
						{String: sptr("a")},
						{String: sptr("c")},
					},
				},
				Body: []*RuleElement{
					{
						Predicate: &Predicate{
							Name: sptr("parent"),
							IDs: []*Term{
								{String: sptr("a")},
								{String: sptr("b")},
							},
						},
					},
					{
						Predicate: &Predicate{
							Name: sptr("parent"),
							IDs: []*Term{
								{String: sptr("b")},
								{String: sptr("c")},
							},
						},
					},
					{
						Expression: &Expression{
							Left: &Expr1{
								Left: &Expr2{
									Left: &Expr3{
										Left: &Expr4{
											Left: &Expr5{
												Left: &ExprTerm{
													Term: &Term{
														Variable: varptr("0"),
													},
												},
											},
										},
									},
								},
								Right: []*OpExpr2{
									{
										Operator: OpGreaterThan,
										Expr3: &Expr3{
											Left: &Expr4{
												Left: &Expr5{
													Left: &ExprTerm{
														Term: &Term{
															Integer: i64ptr(42),
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
					{
						Expression: &Expression{
							Left: &Expr1{
								Left: &Expr2{
									Left: &Expr3{
										Left: &Expr4{
											Left: &Expr5{
												Left: &ExprTerm{
													Term: &Term{
														Variable: varptr("1"),
													},
												},
												Right: []*OpExpr5{
													{
														Operator: OpPrefix,
														Expression: &Expression{
															Left: &Expr1{
																Left: &Expr2{
																	Left: &Expr3{
																		Left: &Expr4{
																			Left: &Expr5{
																				Left: &ExprTerm{
																					Term: &Term{
																						String: sptr("test"),
																					},
																				},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed := &Rule{}
			err := parser.ParseString("test", testCase.Input, parsed)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, parsed)
		})
	}
}

func varptr(s string) *Variable {
	v := Variable(s)
	return &v
}

func sptr(s string) *string {
	return &s
}

func i64ptr(i int64) *int64 {
	return &i
}

func hexsptr(s string) *HexString {
	h := HexString(s)
	return &h
}

func commentptr(s string) *Comment {
	c := Comment(s)
	return &c
}

func boolptr(b bool) *Bool {
	v := Bool(b)
	return &v
}
