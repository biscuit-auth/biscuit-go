package parser

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"github.com/biscuit-auth/biscuit-go"
)

type Comment string

func (c *Comment) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("parser: invalid comment values")
	}
	if !strings.HasPrefix(values[0], "//") {
		return errors.New("parser: invalid comment prefix")
	}
	*c = Comment(strings.TrimSpace(strings.TrimPrefix(values[0], "//")))
	return nil
}

type Variable string

func (v *Variable) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("parser: invalid variable values")
	}
	if !strings.HasPrefix(values[0], "$") {
		return errors.New("parser: invalid variable prefix")
	}
	*v = Variable(strings.TrimPrefix(values[0], "$"))
	return nil
}

type Bool bool

func (b *Bool) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("parser: invalid bool values")
	}
	v, err := strconv.ParseBool(values[0])
	if err != nil {
		return err
	}
	*b = Bool(v)
	return nil
}

type Rule struct {
	Comments []*Comment     `@Comment*`
	Head     *Predicate     `@@`
	Body     []*RuleElement `"<-" @@ ("," @@)*`
}

type RuleElement struct {
	Predicate  *Predicate  `@@`
	Expression *Expression `|@@`
}

type Predicate struct {
	Name *string `@Ident`
	IDs  []*Term `"(" (@@ ("," @@)*)* ")"`
}

type Check struct {
	Queries []*CheckQuery `"check if" @@ ( "or" @@ )*`
}

type CheckQuery struct {
	Body []*RuleElement `@@ ("," @@)*`
}

type Policy struct {
	Allow *Allow `@@`
	Deny  *Deny  `|@@`
}

type Allow struct {
	Queries []*CheckQuery `"allow if" @@ ( "or" @@ )*`
}

type Deny struct {
	Queries []*CheckQuery `"deny if" @@ ( "or" @@ )*`
}

type Term struct {
	Variable *Variable  `@Variable`
	Bytes    *HexString `| @@`
	String   *string    `| @String`
	Date     *string    `| @DateTime`
	Integer  *int64     `| @Int`
	Bool     *Bool      `| @Bool`
	Set      []*Term    `| "[" @@ ("," @@)* "]"`
}

type Value struct {
	Number        *float64    `  @(Float|Int)`
	Variable      *string     `| @Ident`
	Subexpression *Expression `| "(" @@ ")"`
}

type Operator int

const (
	OpMul Operator = iota
	OpDiv
	OpAdd
	OpSub
	OpAnd
	OpOr
	OpLessOrEqual
	OpGreaterOrEqual
	OpLessThan
	OpGreaterThan
	OpEqual
	OpContains
	OpPrefix
	OpSuffix
	OpMatches
	OpIntersection
	OpUnion
	OpLength
)

var operatorMap = map[string]Operator{
	"+": OpAdd,
	"-": OpSub, "*": OpMul, "/": OpDiv, "&&": OpAnd, "||": OpOr, "<=": OpLessOrEqual, ">=": OpGreaterOrEqual, "<": OpLessThan, ">": OpGreaterThan,
	"==": OpEqual, "contains": OpContains, "starts_with": OpPrefix, "ends_with": OpSuffix, "matches": OpMatches, "intersection": OpIntersection, "union": OpUnion, "length": OpLength}

func (o *Operator) Capture(s []string) error {
	*o = operatorMap[s[0]]
	return nil
}

type Expression struct {
	Left  *Expr1     `@@`
	Right []*OpExpr1 `@@*`
}

type Expr1 struct {
	Left  *Expr2     `@@`
	Right []*OpExpr2 `@@*`
}

type OpExpr1 struct {
	Operator Operator `@("&&" | "||")`
	Expr2    *Expr2   `@@`
}

type Expr2 struct {
	Left  *Expr3     `@@`
	Right []*OpExpr3 `@@*`
}

type OpExpr2 struct {
	Operator Operator `@("<=" | ">=" | "<" | ">" | "==")`
	Expr3    *Expr3   `@@`
}

type Expr3 struct {
	Left  *Expr4     `@@`
	Right []*OpExpr4 `@@*`
}

type OpExpr3 struct {
	Operator Operator `@("+" | "-")`
	Expr4    *Expr4   `@@`
}

type Expr4 struct {
	Left  *Expr5     `@@`
	Right []*OpExpr5 `@@*`
}

type OpExpr4 struct {
	Operator Operator `@("*" | "/")`
	Expr5    *Expr5   `@@`
}

type Expr5 struct {
	Left  *ExprTerm  `@@`
	Right []*OpExpr5 `@@*`
}

type OpExpr5 struct {
	Operator   Operator      `Dot @("contains" | "starts_with" | "ends_with" | "matches" | "intersection" | "union" | "length")`
	Expression []*Expression `"("  @@* ")"`
}

type ExprTerm struct {
	Unary *Unary `@@`
	Term  *Term  `|@@`
}

type Unary struct {
	Negate *Negate `@@`
	Parens *Parens `|@@`
	//Length *Length `|@@`
}

type Parens struct {
	Expression *Expression `"("  @@ ")"`
}

type Length struct {
	Term *Term `@@ Dot "length()"`
}

type Negate struct {
	Expr5 *Expr5 `"!" @@`
}

func (e *Expression) ToExpr(expr *biscuit.Expression) {
	e.Left.ToExpr(expr)

	for _, op := range e.Right {
		op.ToExpr(expr)
	}
}

func (e *Expr1) ToExpr(expr *biscuit.Expression) {
	e.Left.ToExpr(expr)

	for _, op := range e.Right {
		op.ToExpr(expr)
	}
}

func (e *Expr2) ToExpr(expr *biscuit.Expression) {
	e.Left.ToExpr(expr)

	for _, op := range e.Right {
		op.ToExpr(expr)
	}
}

func (e *Expr3) ToExpr(expr *biscuit.Expression) {
	e.Left.ToExpr(expr)

	for _, op := range e.Right {
		op.ToExpr(expr)
	}
}

func (e *Expr4) ToExpr(expr *biscuit.Expression) {
	e.Left.ToExpr(expr)

	for _, op := range e.Right {
		op.ToExpr(expr)
	}
}

func (e *Expr5) ToExpr(expr *biscuit.Expression) {
	e.Left.ToExpr(expr)

	for _, op := range e.Right {
		op.ToExpr(expr)
	}
}

func (e *ExprTerm) ToExpr(expr *biscuit.Expression) {

	switch {
	case e.Unary != nil:
		switch {
		case (*e.Unary).Negate != nil:
			(*e.Unary).Negate.Expr5.ToExpr(expr)
			*expr = append(*expr, biscuit.UnaryNegate)

		case (*e.Unary).Parens != nil:
			(*e.Unary).Negate.Expr5.ToExpr(expr)
			*expr = append(*expr, biscuit.UnaryParens)
		}
	case e.Term != nil:
		//FIXME: error management
		term, _ := e.Term.ToBiscuit()
		*expr = append(*expr, biscuit.Value{Term: term})
	}
}

func (e *OpExpr1) ToExpr(expr *biscuit.Expression) {
	e.Expr2.ToExpr(expr)
	e.Operator.ToExpr(expr)
}

func (e *OpExpr2) ToExpr(expr *biscuit.Expression) {
	e.Expr3.ToExpr(expr)
	e.Operator.ToExpr(expr)
}

func (e *OpExpr3) ToExpr(expr *biscuit.Expression) {
	e.Expr4.ToExpr(expr)
	e.Operator.ToExpr(expr)
}

func (e *OpExpr4) ToExpr(expr *biscuit.Expression) {
	e.Expr5.ToExpr(expr)
	e.Operator.ToExpr(expr)
}

func (e *OpExpr5) ToExpr(expr *biscuit.Expression) {
	for _, argument := range e.Expression {
		argument.ToExpr(expr)
	}
	e.Operator.ToExpr(expr)
}

func (op *Operator) ToExpr(expr *biscuit.Expression) {

	var biscuit_op biscuit.Op
	switch *op {
	case OpAnd:
		biscuit_op = biscuit.BinaryAnd
	case OpOr:
		biscuit_op = biscuit.BinaryOr
	case OpMul:
		biscuit_op = biscuit.BinaryMul
	case OpDiv:
		biscuit_op = biscuit.BinaryDiv
	case OpAdd:
		biscuit_op = biscuit.BinaryAdd
	case OpSub:
		biscuit_op = biscuit.BinarySub
	case OpLessOrEqual:
		biscuit_op = biscuit.BinaryLessOrEqual
	case OpGreaterOrEqual:
		biscuit_op = biscuit.BinaryGreaterOrEqual
	case OpLessThan:
		biscuit_op = biscuit.BinaryLessThan
	case OpGreaterThan:
		biscuit_op = biscuit.BinaryGreaterThan
	case OpEqual:
		biscuit_op = biscuit.BinaryEqual
	case OpContains:
		biscuit_op = biscuit.BinaryContains
	case OpPrefix:
		biscuit_op = biscuit.BinaryPrefix
	case OpSuffix:
		biscuit_op = biscuit.BinarySuffix
	case OpMatches:
		biscuit_op = biscuit.BinaryRegex
	case OpLength:
		biscuit_op = biscuit.UnaryLength
	case OpIntersection:
		biscuit_op = biscuit.BinaryIntersection
	case OpUnion:
		biscuit_op = biscuit.BinaryUnion
	}

	*expr = append(*expr, biscuit_op)
}

type Set struct {
	Not    bool        `@"not"? "in"`
	Bytes  []HexString `("[" ( @@ ("," @@)*)+ "]"`
	String []string    `| "[" (@String ("," @String)*)+ "]"`
	Int    []int64     `| "[" (@Int ("," @Int)*)+ "]")`
}

type HexString string

func (h *HexString) Parse(lex *lexer.PeekingLexer) error {
	token, err := lex.Peek(0)
	if err != nil {
		return err
	}

	if token.Value != "hex:" {
		return participle.NextMatch
	}
	_, err = lex.Next()
	if err != nil {
		return err
	}

	content, err := lex.Next()
	if err != nil {
		return err
	}

	*h = HexString(content.Value)

	return nil
}

func (h *HexString) Decode() ([]byte, error) {
	return hex.DecodeString(string(*h))
}

func (h *HexString) String() string {
	return string(*h)
}

func (p *Predicate) ToBiscuit() (*biscuit.Predicate, error) {
	terms := make([]biscuit.Term, 0, len(p.IDs))
	for _, a := range p.IDs {
		biscuitTerm, err := a.ToBiscuit()
		if err != nil {
			return nil, err
		}
		terms = append(terms, biscuitTerm)
	}

	return &biscuit.Predicate{
		Name: *p.Name,
		IDs:  terms,
	}, nil
}

func (a *Term) ToBiscuit() (biscuit.Term, error) {
	var biscuitTerm biscuit.Term
	switch {
	case a.Integer != nil:
		biscuitTerm = biscuit.Integer(*a.Integer)
	case a.String != nil:
		biscuitTerm = biscuit.String(*a.String)
	case a.Variable != nil:
		biscuitTerm = biscuit.Variable(*a.Variable)
	case a.Date != nil:
		date, err := time.Parse(time.RFC3339, *a.Date)
		if err != nil {
			return nil, fmt.Errorf("parser: failed to decode date: %v", err)
		}

		biscuitTerm = biscuit.Date(date)
	case a.Bytes != nil:
		b, err := a.Bytes.Decode()
		if err != nil {
			return nil, fmt.Errorf("parser: failed to decode hex string: %v", err)
		}
		biscuitTerm = biscuit.Bytes(b)
	case a.Bool != nil:
		biscuitTerm = biscuit.Bool(*a.Bool)
	case a.Set != nil:
		biscuitSet := make(biscuit.Set, 0, len(a.Set))
		for _, term := range a.Set {
			setTerm, err := term.ToBiscuit()
			if err != nil {
				return nil, err
			}
			if setTerm.Type() == biscuit.TermTypeVariable {
				return nil, ErrVariableInSet
			}
			biscuitSet = append(biscuitSet, setTerm)
		}
		biscuitTerm = biscuitSet
	default:
		return nil, errors.New("parser: unsupported predicate, must be one of integer, string, variable, or bytes")
	}

	return biscuitTerm, nil
}

func (r *Rule) ToBiscuit() (*biscuit.Rule, error) {
	body := []biscuit.Predicate{}
	expressions := make([]biscuit.Expression, 0)

	for _, p := range r.Body {
		switch {
		case p.Predicate != nil:
			{
				predicate, err := (*p.Predicate).ToBiscuit()
				if err != nil {
					return nil, err
				}
				body = append(body, *predicate)
			}
		case p.Expression != nil:
			{
				var expr biscuit.Expression
				(*p.Expression).ToExpr(&expr)

				expressions = append(expressions, expr)
			}
		}
	}

	head, err := r.Head.ToBiscuit()
	if err != nil {
		return nil, err
	}

	return &biscuit.Rule{
		Head:        *head,
		Body:        body,
		Expressions: expressions,
	}, nil
}

func (c *Check) ToBiscuit() (*biscuit.Check, error) {
	queries := make([]biscuit.Rule, 0, len(c.Queries))
	for _, q := range c.Queries {
		r, err := q.ToBiscuit()
		if err != nil {
			return nil, err
		}

		queries = append(queries, *r)
	}

	return &biscuit.Check{
		Queries: queries,
	}, nil
}

func (r *CheckQuery) ToBiscuit() (*biscuit.Rule, error) {
	body := []biscuit.Predicate{}
	expressions := make([]biscuit.Expression, 0)

	for _, p := range r.Body {
		switch {
		case p.Predicate != nil:
			{
				predicate, err := (*p.Predicate).ToBiscuit()
				if err != nil {
					return nil, err
				}
				body = append(body, *predicate)
			}
		case p.Expression != nil:
			{
				var expr biscuit.Expression
				(*p.Expression).ToExpr(&expr)

				expressions = append(expressions, expr)
			}
		}
	}

	head := &biscuit.Predicate{
		Name: "query",
		IDs:  []biscuit.Term{},
	}

	return &biscuit.Rule{
		Head:        *head,
		Body:        body,
		Expressions: expressions,
	}, nil
}

func (p *Policy) ToBiscuit() (*biscuit.Policy, error) {
	var parsedQueries []*CheckQuery
	var kind biscuit.PolicyKind
	switch {
	case p.Allow != nil:
		{
			parsedQueries = p.Allow.Queries
			kind = biscuit.PolicyKindAllow
			break
		}
	case p.Deny != nil:
		{
			parsedQueries = p.Allow.Queries
			kind = biscuit.PolicyKindDeny
			break
		}
	}
	queries := make([]biscuit.Rule, 0, len(parsedQueries))
	for _, q := range parsedQueries {
		r, err := q.ToBiscuit()
		if err != nil {
			return nil, err
		}

		queries = append(queries, *r)
	}

	return &biscuit.Policy{
		Queries: queries,
		Kind:    kind,
	}, nil
}
