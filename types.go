// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
)

// Block versions this library accepts: 3 is datalog v3.0, 4 is datalog v3.1,
// 5 is datalog v3.2.
const MinSchemaVersion uint32 = 3
const MaxSchemaVersion uint32 = 5

// Block versions, by the datalog release that introduced them.
const (
	blockVersion3_0 uint32 = 3
	blockVersion3_1 uint32 = 4
	// blockVersion3_2 is the minimum for a third-party block.
	blockVersion3_2 uint32 = 5
)

// schemaVersion is the lowest block version able to carry the given content.
func schemaVersion(scopes []datalog.Scope, rules []datalog.Rule, checks []datalog.Check) uint32 {
	if hasScopes(scopes, rules, checks) {
		return blockVersion3_1
	}
	for _, c := range checks {
		if c.Kind != datalog.CheckKindOne {
			return blockVersion3_1
		}
		for _, q := range c.Queries {
			if containsV31Op(q.Expressions) {
				return blockVersion3_1
			}
		}
	}
	for _, r := range rules {
		if containsV31Op(r.Expressions) {
			return blockVersion3_1
		}
	}
	return blockVersion3_0
}

// containsV31Op reports whether an expression uses an operator introduced
// in datalog v3.1: bitwise operators and !==.
func containsV31Op(expressions []datalog.Expression) bool {
	for _, e := range expressions {
		for _, op := range e {
			b, ok := op.(datalog.BinaryOp)
			if !ok {
				continue
			}
			switch b.BinaryOpFunc.Type() {
			case datalog.BinaryBitwiseAnd, datalog.BinaryBitwiseOr, datalog.BinaryBitwiseXor, datalog.BinaryNotEqual:
				return true
			}
		}
	}
	return false
}

// defaultSymbolTable predefines some symbols available in every implementation, to avoid
// transmitting them with every token
var defaultSymbolTable = &datalog.SymbolTable{}

type Block struct {
	symbols *datalog.SymbolTable
	facts   *datalog.FactSet
	rules   []datalog.Rule
	checks  []datalog.Check
	// scopes is the block-level `trusting` clause, the default scope of
	// the rules and checks of the block.
	scopes []datalog.Scope
	// publicKeys are the keys the scopes of this block add to the key
	// table of the token.
	publicKeys []datalog.PublicKey
	// externalKey is the key a third party signed the block with; nil for
	// a first-party block. A third-party block has its own symbol and key
	// tables, which the token tables do not include.
	externalKey *datalog.PublicKey
	context     string
	version     uint32
}

// symbolTable is the table the content of the block refers to: the token's
// for a first-party block, the defaults plus its own for a third-party block.
func (b *Block) symbolTable(token *datalog.SymbolTable) *datalog.SymbolTable {
	if b.externalKey == nil {
		return token
	}
	symbols := defaultSymbolTable.Clone()
	symbols.Extend(b.symbols)
	return symbols
}

func (b *Block) Code(symbols *datalog.SymbolTable) string {
	debug := &datalog.SymbolDebugger{
		SymbolTable: symbols,
	}
	facts := make([]string, len(*b.facts))
	for i, f := range *b.facts {
		facts[i] = debug.Predicate(f.Predicate)
	}
	rules := make([]string, len(b.rules))
	for i, r := range b.rules {
		rules[i] = debug.Rule(r)
	}

	checks := make([]string, len(b.checks))
	for i, c := range b.checks {
		checks[i] = debug.Check(c)
	}

	var scopes string
	if len(b.scopes) > 0 {
		scopes = strings.TrimPrefix(datalog.ScopesString(b.scopes), " ") + ";\n"
	}

	return fmt.Sprintf(`Block {
		%s%v
		%s
		%s
	}`,
		scopes,
		strings.Join(facts, ";\n"),
		strings.Join(rules, ";\n"),
		strings.Join(checks, ";\n"),
	)
}

func (b *Block) String(symbols *datalog.SymbolTable) string {
	debug := &datalog.SymbolDebugger{
		SymbolTable: symbols,
	}
	rules := make([]string, len(b.rules))
	for i, r := range b.rules {
		rules[i] = debug.Rule(r)
	}

	checks := make([]string, len(b.checks))
	for i, c := range b.checks {
		checks[i] = debug.Check(c)
	}

	return fmt.Sprintf(`Block {
		symbols: %+q
		context: %q
		facts: %v
		rules: %v
		checks: [%s]
		version: %d
	}`,
		*b.symbols,
		b.context,
		debug.FactSet(b.facts),
		rules,
		strings.Join(checks, ", "),
		b.version,
	)
}

type FactSet []Fact

func (fs FactSet) String() string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.String())
	}

	var outStr string
	if len(out) > 0 {
		outStr = fmt.Sprintf("\n\t%s\n", strings.Join(out, ",\n\t"))
	}

	return fmt.Sprintf("[%s]", outStr)
}

type ParsedBlock struct {
	Facts  FactSet
	Rules  []Rule
	Checks []Check
	Scopes []Scope
}

type ParsedAuthorizer struct {
	Policies []Policy
	Block    ParsedBlock
}

type Fact struct {
	Predicate
}

func (f Fact) convert(symbols *datalog.SymbolTable) datalog.Fact {
	return datalog.Fact{
		Predicate: f.Predicate.convert(symbols),
	}
}
func (f Fact) String() string {
	return f.Predicate.String()
}

func fromDatalogFact(symbols *datalog.SymbolTable, f datalog.Fact) (*Fact, error) {
	pred, err := fromDatalogPredicate(symbols, f.Predicate)
	if err != nil {
		return nil, err
	}

	return &Fact{
		Predicate: *pred,
	}, nil
}

func fromDatalogPredicate(symbols *datalog.SymbolTable, p datalog.Predicate) (*Predicate, error) {
	terms := make([]Term, 0, len(p.Terms))
	for _, id := range p.Terms {
		a, err := fromDatalogID(symbols, id)
		if err != nil {
			return nil, err
		}
		terms = append(terms, a)
	}

	return &Predicate{
		Name: symbols.Str(p.Name),
		IDs:  terms,
	}, nil
}

func fromDatalogID(symbols *datalog.SymbolTable, id datalog.Term) (Term, error) {
	var a Term
	switch id.Type() {
	case datalog.TermTypeVariable:
		a = Variable(symbols.Str(datalog.String(id.(datalog.Variable))))
	case datalog.TermTypeInteger:
		a = Integer(id.(datalog.Integer))
	case datalog.TermTypeString:
		a = String(symbols.Str(id.(datalog.String)))
	case datalog.TermTypeDate:
		a = Date(time.Unix(int64(id.(datalog.Date)), 0))
	case datalog.TermTypeBytes:
		a = Bytes(id.(datalog.Bytes))
	case datalog.TermTypeBool:
		a = Bool(id.(datalog.Bool))
	case datalog.TermTypeSet:
		setIDs := id.(datalog.Set)
		set := make(Set, 0, len(setIDs))
		for _, i := range setIDs {
			setTerm, err := fromDatalogID(symbols, i)
			if err != nil {
				return nil, err
			}
			set = append(set, setTerm)
		}
		a = set
	default:
		return nil, fmt.Errorf("unsupported term type: %v", id.Type())
	}

	return a, nil
}

type Rule struct {
	Head        Predicate
	Body        []Predicate
	Expressions []Expression
	// Scopes is the `trusting` clause; empty means the scopes of the block.
	Scopes []Scope
}

func (r Rule) convert(symbols *datalog.SymbolTable) datalog.Rule {
	dlBody := make([]datalog.Predicate, len(r.Body))
	for i, p := range r.Body {
		dlBody[i] = p.convert(symbols)
	}

	dlExpressions := make([]datalog.Expression, len(r.Expressions))
	for i, e := range r.Expressions {
		dlExpressions[i] = e.convert(symbols)
	}
	return datalog.Rule{
		Head:        r.Head.convert(symbols),
		Body:        dlBody,
		Expressions: dlExpressions,
		Scopes:      slices.Clone(r.Scopes),
	}
}

func fromDatalogRule(symbols *datalog.SymbolTable, dlRule datalog.Rule) (*Rule, error) {
	head, err := fromDatalogPredicate(symbols, dlRule.Head)
	if err != nil {
		return nil, fmt.Errorf("failed to convert datalog rule head: %v", err)
	}

	body := make([]Predicate, len(dlRule.Body))
	for i, dlPred := range dlRule.Body {
		pred, err := fromDatalogPredicate(symbols, dlPred)
		if err != nil {
			return nil, fmt.Errorf("failed to convert datalog rule body: %v", err)
		}
		body[i] = *pred
	}

	expressions := make([]Expression, len(dlRule.Expressions))
	for i, dlExpr := range dlRule.Expressions {
		expr, err := fromDatalogExpression(symbols, dlExpr)
		if err != nil {
			return nil, fmt.Errorf("failed to convert datalog rule expression: %v", err)
		}
		expressions[i] = expr
	}

	return &Rule{
		Head:        *head,
		Body:        body,
		Expressions: expressions,
		Scopes:      slices.Clone(dlRule.Scopes),
	}, nil
}

type Expression []Op

func (e Expression) convert(symbols *datalog.SymbolTable) datalog.Expression {
	expr := make(datalog.Expression, len(e))
	for i, elt := range e {
		expr[i] = elt.convert(symbols)
	}
	return expr
}

func fromDatalogExpression(symbols *datalog.SymbolTable, dlExpr datalog.Expression) (Expression, error) {
	expr := make(Expression, len(dlExpr))
	for i, dlOP := range dlExpr {
		switch dlOP.Type() {
		case datalog.OpTypeValue:
			v, err := fromDatalogValueOp(symbols, dlOP.(datalog.Value))
			if err != nil {
				return nil, fmt.Errorf("failed to convert datalog expression value: %w", err)
			}
			expr[i] = v
		case datalog.OpTypeUnary:
			u, err := fromDatalogUnaryOp(symbols, dlOP.(datalog.UnaryOp))
			if err != nil {
				return nil, fmt.Errorf("failed to convert datalog unary expression: %w", err)
			}
			expr[i] = u
		case datalog.OpTypeBinary:
			b, err := fromDatalogBinaryOp(symbols, dlOP.(datalog.BinaryOp))
			if err != nil {
				return nil, fmt.Errorf("failed to convert datalog binary expression: %w", err)
			}
			expr[i] = b
		default:
			return nil, fmt.Errorf("unsupported datalog expression type: %v", dlOP.Type())
		}
	}
	return expr, nil
}

type Op interface {
	Type() OpType
	convert(symbols *datalog.SymbolTable) datalog.Op
}

type OpType byte

const (
	OpTypeValue OpType = iota
	OpTypeUnary
	OpTypeBinary
)

type Value struct {
	Term Term
}

func (v Value) Type() OpType {
	return OpTypeValue
}
func (v Value) convert(symbols *datalog.SymbolTable) datalog.Op {
	return datalog.Value{ID: v.Term.convert(symbols)}
}
func fromDatalogValueOp(symbols *datalog.SymbolTable, dlValue datalog.Value) (Op, error) {
	term, err := fromDatalogID(symbols, dlValue.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert datalog expression value: %v", err)
	}
	return Value{Term: term}, nil
}

type unaryOpType byte

type UnaryOp unaryOpType

const (
	UnaryUndefined UnaryOp = iota
	UnaryNegate
	UnaryParens
	UnaryLength
)

func (UnaryOp) Type() OpType {
	return OpTypeUnary
}
func (op UnaryOp) convert(symbols *datalog.SymbolTable) datalog.Op {
	switch op {
	case UnaryNegate:
		return datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}}
	case UnaryParens:
		return datalog.UnaryOp{UnaryOpFunc: datalog.Parens{}}
	case UnaryLength:
		return datalog.UnaryOp{UnaryOpFunc: datalog.Length{}}
	default:
		panic(fmt.Sprintf("biscuit: cannot convert invalid unary op type: %v", op))
	}
}

func fromDatalogUnaryOp(symbols *datalog.SymbolTable, dlUnary datalog.UnaryOp) (Op, error) {
	switch dlUnary.UnaryOpFunc.Type() {
	case datalog.UnaryNegate:
		return UnaryNegate, nil
	case datalog.UnaryParens:
		return UnaryParens, nil
	case datalog.UnaryLength:
		return UnaryLength, nil
	default:
		return UnaryUndefined, fmt.Errorf("unsupported datalog unary op: %v", dlUnary.UnaryOpFunc.Type())
	}
}

type binaryOpType byte

type BinaryOp binaryOpType

const (
	BinaryUndefined BinaryOp = iota
	BinaryLessThan
	BinaryLessOrEqual
	BinaryGreaterThan
	BinaryGreaterOrEqual
	BinaryEqual
	BinaryContains
	BinaryPrefix
	BinarySuffix
	BinaryRegex
	BinaryAdd
	BinarySub
	BinaryMul
	BinaryDiv
	BinaryAnd
	BinaryOr
	BinaryIntersection
	BinaryUnion
	// Datalog v3.1 operators; using one makes the block version 4.
	BinaryBitwiseAnd
	BinaryBitwiseOr
	BinaryBitwiseXor
	BinaryNotEqual
)

func (BinaryOp) Type() OpType {
	return OpTypeBinary
}
func (op BinaryOp) convert(symbols *datalog.SymbolTable) datalog.Op {
	switch op {
	case BinaryLessThan:
		return datalog.BinaryOp{BinaryOpFunc: datalog.LessThan{}}
	case BinaryLessOrEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.LessOrEqual{}}
	case BinaryGreaterThan:
		return datalog.BinaryOp{BinaryOpFunc: datalog.GreaterThan{}}
	case BinaryGreaterOrEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.GreaterOrEqual{}}
	case BinaryEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}}
	case BinaryContains:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}}
	case BinaryPrefix:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Prefix{}}
	case BinarySuffix:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Suffix{}}
	case BinaryRegex:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Regex{}}
	case BinaryAdd:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Add{}}
	case BinarySub:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Sub{}}
	case BinaryMul:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Mul{}}
	case BinaryDiv:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Div{}}
	case BinaryAnd:
		return datalog.BinaryOp{BinaryOpFunc: datalog.And{}}
	case BinaryOr:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Or{}}
	case BinaryIntersection:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Intersection{}}
	case BinaryUnion:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Union{}}
	case BinaryBitwiseAnd:
		return datalog.BinaryOp{BinaryOpFunc: datalog.BitwiseAnd{}}
	case BinaryBitwiseOr:
		return datalog.BinaryOp{BinaryOpFunc: datalog.BitwiseOr{}}
	case BinaryBitwiseXor:
		return datalog.BinaryOp{BinaryOpFunc: datalog.BitwiseXor{}}
	case BinaryNotEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.NotEqual{}}
	default:
		panic(fmt.Sprintf("biscuit: cannot convert invalid binary op type: %v", op))
	}
}

func fromDatalogBinaryOp(symbols *datalog.SymbolTable, dbBinary datalog.BinaryOp) (Op, error) {
	switch dbBinary.BinaryOpFunc.Type() {
	case datalog.BinaryLessThan:
		return BinaryLessThan, nil
	case datalog.BinaryLessOrEqual:
		return BinaryLessOrEqual, nil
	case datalog.BinaryGreaterThan:
		return BinaryGreaterThan, nil
	case datalog.BinaryGreaterOrEqual:
		return BinaryGreaterOrEqual, nil
	case datalog.BinaryEqual:
		return BinaryEqual, nil
	case datalog.BinaryContains:
		return BinaryContains, nil
	case datalog.BinaryPrefix:
		return BinaryPrefix, nil
	case datalog.BinarySuffix:
		return BinarySuffix, nil
	case datalog.BinaryRegex:
		return BinaryRegex, nil
	case datalog.BinaryAdd:
		return BinaryAdd, nil
	case datalog.BinarySub:
		return BinarySub, nil
	case datalog.BinaryMul:
		return BinaryMul, nil
	case datalog.BinaryDiv:
		return BinaryDiv, nil
	case datalog.BinaryAnd:
		return BinaryAnd, nil
	case datalog.BinaryOr:
		return BinaryOr, nil
	case datalog.BinaryIntersection:
		return BinaryIntersection, nil
	case datalog.BinaryUnion:
		return BinaryUnion, nil
	case datalog.BinaryBitwiseAnd:
		return BinaryBitwiseAnd, nil
	case datalog.BinaryBitwiseOr:
		return BinaryBitwiseOr, nil
	case datalog.BinaryBitwiseXor:
		return BinaryBitwiseXor, nil
	case datalog.BinaryNotEqual:
		return BinaryNotEqual, nil
	default:
		return BinaryUndefined, fmt.Errorf("unsupported datalog binary op: %v", dbBinary.BinaryOpFunc.Type())
	}
}

// CheckKind selects how the queries of a Check are evaluated.
type CheckKind byte

const (
	// CheckKindOne (`check if`) passes when one query has at least one match.
	CheckKindOne CheckKind = iota
	// CheckKindAll (`check all`) passes when one query has at least one match
	// and every match of that query satisfies its expressions. Requires a
	// datalog v3.1 block (version 4).
	CheckKindAll
)

func (k CheckKind) convert() datalog.CheckKind {
	switch k {
	case CheckKindAll:
		return datalog.CheckKindAll
	default:
		return datalog.CheckKindOne
	}
}

func fromDatalogCheckKind(k datalog.CheckKind) CheckKind {
	switch k {
	case datalog.CheckKindAll:
		return CheckKindAll
	default:
		return CheckKindOne
	}
}

type Check struct {
	Queries []Rule
	Kind    CheckKind
}

func (c Check) convert(symbols *datalog.SymbolTable) datalog.Check {
	queries := make([]datalog.Rule, len(c.Queries))
	for i, q := range c.Queries {
		queries[i] = q.convert(symbols)
	}

	return datalog.Check{
		Queries: queries,
		Kind:    c.Kind.convert(),
	}
}

func fromDatalogCheck(symbols *datalog.SymbolTable, dlCheck datalog.Check) (*Check, error) {
	queries := make([]Rule, len(dlCheck.Queries))
	for i, q := range dlCheck.Queries {
		query, err := fromDatalogRule(symbols, q)
		if err != nil {
			return nil, fmt.Errorf("failed to convert datalog check query: %w", err)
		}
		queries[i] = *query
	}

	return &Check{
		Queries: queries,
		Kind:    fromDatalogCheckKind(dlCheck.Kind),
	}, nil
}

type Predicate struct {
	Name string
	IDs  []Term
}

func (p Predicate) convert(symbols *datalog.SymbolTable) datalog.Predicate {
	var ids []datalog.Term
	for _, a := range p.IDs {
		ids = append(ids, a.convert(symbols))
	}

	return datalog.Predicate{
		Name:  symbols.Insert(p.Name),
		Terms: ids,
	}
}
func (p Predicate) String() string {
	terms := make([]string, 0, len(p.IDs))
	for _, a := range p.IDs {
		terms = append(terms, a.String())
	}
	return fmt.Sprintf("%s(%s)", p.Name, strings.Join(terms, ", "))
}

type TermType byte

const (
	TermTypeSymbol TermType = iota
	TermTypeVariable
	TermTypeInteger
	TermTypeString
	TermTypeDate
	TermTypeBytes
	TermTypeBool
	TermTypeSet
)

type Term interface {
	Type() TermType
	String() string
	convert(symbols *datalog.SymbolTable) datalog.Term
}

type Variable string

func (a Variable) Type() TermType { return TermTypeVariable }
func (a Variable) convert(symbols *datalog.SymbolTable) datalog.Term {
	return datalog.Variable(symbols.Insert(string(a)))
}
func (a Variable) String() string { return fmt.Sprintf("$%s", string(a)) }

type Integer int64

func (a Integer) Type() TermType { return TermTypeInteger }
func (a Integer) convert(symbols *datalog.SymbolTable) datalog.Term {
	return datalog.Integer(a)
}
func (a Integer) String() string { return fmt.Sprintf("%d", a) }

type String string

func (a String) Type() TermType { return TermTypeString }
func (a String) convert(symbols *datalog.SymbolTable) datalog.Term {
	return datalog.String(symbols.Insert(string(a)))
}
func (a String) String() string { return fmt.Sprintf("%q", string(a)) }

type Date time.Time

func (a Date) Type() TermType { return TermTypeDate }
func (a Date) convert(symbols *datalog.SymbolTable) datalog.Term {
	return datalog.Date(time.Time(a).Unix())
}
func (a Date) String() string { return time.Time(a).Format(time.RFC3339) }

type Bytes []byte

func (a Bytes) Type() TermType { return TermTypeBytes }
func (a Bytes) convert(symbols *datalog.SymbolTable) datalog.Term {
	return datalog.Bytes(a)
}
func (a Bytes) String() string { return fmt.Sprintf("hex:%s", hex.EncodeToString(a)) }

type Bool bool

func (b Bool) Type() TermType { return TermTypeBool }
func (b Bool) convert(symbols *datalog.SymbolTable) datalog.Term {
	return datalog.Bool(b)
}
func (b Bool) String() string { return fmt.Sprintf("%t", b) }

type Set []Term

func (a Set) Type() TermType { return TermTypeSet }
func (a Set) convert(symbols *datalog.SymbolTable) datalog.Term {
	datalogSet := make(datalog.Set, 0, len(a))
	for _, e := range a {
		datalogSet = append(datalogSet, e.convert(symbols))
	}
	return datalogSet
}
func (a Set) String() string {
	elts := make([]string, 0, len(a))
	for _, e := range a {
		elts = append(elts, e.String())
	}
	if len(elts) == 0 {
		return "{,}"
	}
	sort.Strings(elts)
	return fmt.Sprintf("{%s}", strings.Join(elts, ", "))
}

type PolicyKind byte

const (
	PolicyKindAllow = iota
	PolicyKindDeny
)

var (
	// DefaultAllowPolicy allows the biscuit to verify sucessfully as long as all its checks generate some facts.
	DefaultAllowPolicy = Policy{Kind: PolicyKindAllow, Queries: []Rule{{Head: Predicate{Name: "allow"}}}}
	// DefaultDenyPolicy makes the biscuit verification fail in all cases.
	DefaultDenyPolicy = Policy{Kind: PolicyKindDeny, Queries: []Rule{{Head: Predicate{Name: "deny"}}}}
)

type Policy struct {
	Queries []Rule
	Kind    PolicyKind
}
