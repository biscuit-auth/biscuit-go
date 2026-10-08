// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"
)

// maxStackSize defines the maximum number of elements that can be stored on the stack.
// Trying to store more than maxStackSize elements returns an error.
const maxStackSize = 1000

var (
	ErrExprDivByZero = errors.New("datalog: Div by zero")
	ErrInt64Overflow = errors.New("datalog: expression overflowed int64")
	// ErrShadowedVariable is returned when a closure parameter has the name
	// of a variable already bound in the expression.
	ErrShadowedVariable = errors.New("datalog: closure parameter shadows a variable")
)

type Expression []Op

func (e *Expression) Evaluate(values map[Variable]*Term, symbols *SymbolTable) (Term, error) {
	s := &stack{}

	for _, op := range *e {
		switch op.Type() {
		case OpTypeValue:
			id := op.(Value).ID
			switch id.Type() {
			case TermTypeVariable:
				idptr, ok := values[id.(Variable)]
				if !ok {
					return nil, fmt.Errorf("datalog: expressions: unknown variable %d", id.(Variable))
				}
				id = *idptr
			default: // do nothing
			}
			err := s.Push(stackElem{term: id})
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: stack overflow")
			}
		case OpTypeClosure:
			closure := op.(Closure)
			if err := s.Push(stackElem{closure: &closure}); err != nil {
				return nil, fmt.Errorf("datalog: expressions: stack overflow")
			}
		case OpTypeUnary:
			v, err := s.PopTerm()
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: failed to pop unary value: %w", err)
			}

			res, err := op.(UnaryOp).Eval(v, symbols)
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: unary eval failed: %w", err)
			}
			err = s.Push(stackElem{term: res})
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: stack overflow")
			}
		case OpTypeBinary:
			right, err := s.Pop()
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: failed to pop binary right value: %w", err)
			}
			left, err := s.PopTerm()
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: failed to pop binary left value: %w", err)
			}

			var res Term
			if right.closure != nil {
				res, err = evalWithClosure(op.(BinaryOp), left, *right.closure, values, symbols)
			} else {
				res, err = op.(BinaryOp).Eval(left, right.term, symbols)
			}
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: binary eval failed: %w", err)
			}
			err = s.Push(stackElem{term: res})
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: stack overflow")
			}
		default:
			return nil, fmt.Errorf("datalog: expressions: unsupported Op: %v", op.Type())
		}
	}

	// after processing all operations, there must be a single value left in the stack
	if len(*s) != 1 {
		return nil, fmt.Errorf("datalog: expressions: invalid resulting stack: %#v", *s)
	}

	return s.PopTerm()
}

// evalWithClosure applies a binary operator whose right operand is a closure.
// The closure runs with its parameters bound on top of the current variables;
// a parameter may not have the name of a bound variable.
func evalWithClosure(op BinaryOp, left Term, closure Closure, values map[Variable]*Term, symbols *SymbolTable) (Term, error) {
	f, ok := op.BinaryOpFunc.(ClosureOpFunc)
	if !ok {
		return nil, fmt.Errorf("datalog: %s does not take a closure", op.Print("", ""))
	}
	for _, p := range closure.Params {
		if _, bound := values[p]; bound {
			return nil, ErrShadowedVariable
		}
	}
	scope := make(map[Variable]*Term, len(values)+len(closure.Params))
	for k, v := range values {
		scope[k] = v
	}
	return f.EvalClosure(left, closure, scope, symbols)
}

func (e *Expression) Print(symbols *SymbolTable) string {
	s := &stringstack{}

	for _, op := range *e {
		switch op.Type() {
		case OpTypeValue:
			if err := s.Push(SymbolDebugger{SymbolTable: symbols}.Term(op.(Value).ID)); err != nil {
				return "<invalid expression: stack overflow>"
			}
		case OpTypeClosure:
			if err := s.Push(op.(Closure).Print(symbols)); err != nil {
				return "<invalid expression: stack overflow>"
			}
		case OpTypeUnary:
			v, err := s.Pop()
			if err != nil {
				return "<invalid expression: unary operation failed to pop value>"
			}
			res := op.(UnaryOp).Print(v)
			err = s.Push(res)
			if err != nil {
				return "<invalid expression: stack overflow>"
			}
		case OpTypeBinary:
			right, err := s.Pop()
			if err != nil {
				return "<invalid expression: binary operation failed to pop right value>"
			}
			left, err := s.Pop()
			if err != nil {
				return "<invalid expression: binary operation failed to pop left value>"
			}
			res := op.(BinaryOp).Print(left, right)
			err = s.Push(res)
			if err != nil {
				return "<invalid expression: stack overflow>"
			}
		default:
			return fmt.Sprintf("<invalid expression: unsupported op type %v>", op.Type())
		}
	}

	if len(*s) == 1 {
		v, err := s.Pop()
		if err != nil {
			return "<invalid expression: failed to pop result value>"
		}
		return v
	}

	return "<invalid expression: invalid resulting stack>"
}

type OpType byte

const (
	OpTypeValue OpType = iota
	OpTypeUnary
	OpTypeBinary
	// OpTypeClosure is datalog v3.3.
	OpTypeClosure
)

type Op interface {
	Type() OpType
}

// Closure is an expression evaluated by the operator that consumes it, with
// Params bound by that operator: the right side of a lazy && or ||, or the
// predicate of .all() and .any(). Datalog v3.3.
type Closure struct {
	Params []Variable
	Body   Expression
}

func (Closure) Type() OpType {
	return OpTypeClosure
}

// Print renders the closure as `$p -> body`, or just the body without
// parameters.
func (c Closure) Print(symbols *SymbolTable) string {
	body := c.Body.Print(symbols)
	if len(c.Params) == 0 {
		return body
	}
	params := make([]string, len(c.Params))
	for i, p := range c.Params {
		params[i] = "$" + symbols.Var(p)
	}
	return fmt.Sprintf("%s -> %s", strings.Join(params, ", "), body)
}

// ClosureOpFunc is a binary operator whose right operand is a closure.
type ClosureOpFunc interface {
	BinaryOpFunc
	// EvalClosure receives the variables of the expression, which it may
	// extend with the closure parameters.
	EvalClosure(left Term, closure Closure, values map[Variable]*Term, symbols *SymbolTable) (Term, error)
}

type Value struct {
	ID Term
}

func (v Value) Type() OpType {
	return OpTypeValue
}

type UnaryOp struct {
	UnaryOpFunc
}

func (UnaryOp) Type() OpType {
	return OpTypeUnary
}
func (op UnaryOp) Print(value string) string {
	var out string
	switch op.UnaryOpFunc.Type() {
	case UnaryNegate:
		out = fmt.Sprintf("!%s", value)
	case UnaryParens:
		out = fmt.Sprintf("(%s)", value)
	case UnaryLength:
		out = fmt.Sprintf("%s.length()", value)
	case UnaryTypeOf:
		out = fmt.Sprintf("%s.type()", value)
	default:
		out = fmt.Sprintf("unknown(%s)", value)
	}
	return out
}

type UnaryOpFunc interface {
	Type() UnaryOpType
	Eval(value Term, symbols *SymbolTable) (Term, error)
}

type UnaryOpType byte

const (
	UnaryNegate UnaryOpType = iota
	UnaryParens
	UnaryLength
	// UnaryTypeOf is datalog v3.3.
	UnaryTypeOf
)

// TypeOf is .type(): the name of the type of a value, as a String.
type TypeOf struct{}

func (TypeOf) Type() UnaryOpType {
	return UnaryTypeOf
}
func (TypeOf) Eval(value Term, symbols *SymbolTable) (Term, error) {
	var name string
	switch value.Type() {
	case TermTypeInteger:
		name = "integer"
	case TermTypeString:
		name = "string"
	case TermTypeDate:
		name = "date"
	case TermTypeBytes:
		name = "bytes"
	case TermTypeBool:
		name = "bool"
	case TermTypeSet:
		name = "set"
	case TermTypeNull:
		name = "null"
	case TermTypeArray:
		name = "array"
	case TermTypeMap:
		name = "map"
	default:
		return nil, fmt.Errorf("datalog: unexpected TypeOf value type: %d", value.Type())
	}
	return symbols.Insert(name), nil
}

// Negate returns the negation of a value.
// It only accepts a Bool value.
type Negate struct{}

func (Negate) Type() UnaryOpType {
	return UnaryNegate
}
func (Negate) Eval(value Term, _ *SymbolTable) (Term, error) {
	var out Term
	switch value.Type() {
	case TermTypeBool:
		out = !value.(Bool)
	default:
		return nil, fmt.Errorf("datalog: unexpected Negate value type: %d", value.Type())
	}

	return out, nil
}

// Parens allows expression priority and grouping (like parenthesis in math operations)
// it is a no-op, but is used to print back the expressions properly, putting their value
// inside parenthesis.
type Parens struct{}

func (Parens) Type() UnaryOpType {
	return UnaryParens
}
func (Parens) Eval(value Term, _ *SymbolTable) (Term, error) {
	return value, nil
}

// Length returns the length of a value.
// It accepts String, Bytes and Set
type Length struct{}

func (Length) Type() UnaryOpType {
	return UnaryLength
}
func (Length) Eval(value Term, symbols *SymbolTable) (Term, error) {
	var out Term
	switch value.Type() {
	case TermTypeString:
		str := symbols.Str(value.(String))
		out = Integer(len(str))
	case TermTypeBytes:
		out = Integer(len(value.(Bytes)))
	case TermTypeSet:
		out = Integer(len(value.(Set)))
	case TermTypeArray:
		out = Integer(len(value.(Array)))
	case TermTypeMap:
		out = Integer(len(value.(Map)))
	default:
		return nil, fmt.Errorf("datalog: unexpected Length value type: %d", value.Type())
	}
	return out, nil
}

type BinaryOp struct {
	BinaryOpFunc
}

func (BinaryOp) Type() OpType {
	return OpTypeBinary
}
func (op BinaryOp) Print(left, right string) string {
	var out string
	switch op.BinaryOpFunc.Type() {
	case BinaryLessThan:
		out = fmt.Sprintf("%s < %s", left, right)
	case BinaryLessOrEqual:
		out = fmt.Sprintf("%s <= %s", left, right)
	case BinaryGreaterThan:
		out = fmt.Sprintf("%s > %s", left, right)
	case BinaryGreaterOrEqual:
		out = fmt.Sprintf("%s >= %s", left, right)
	case BinaryEqual:
		out = fmt.Sprintf("%s === %s", left, right)
	case BinaryContains:
		out = fmt.Sprintf("%s.contains(%s)", left, right)
	case BinaryPrefix:
		out = fmt.Sprintf("%s.starts_with(%s)", left, right)
	case BinarySuffix:
		out = fmt.Sprintf("%s.ends_with(%s)", left, right)
	case BinaryRegex:
		out = fmt.Sprintf("%s.matches(%s)", left, right)
	case BinaryAdd:
		out = fmt.Sprintf("%s + %s", left, right)
	case BinarySub:
		out = fmt.Sprintf("%s - %s", left, right)
	case BinaryMul:
		out = fmt.Sprintf("%s * %s", left, right)
	case BinaryDiv:
		out = fmt.Sprintf("%s / %s", left, right)
	case BinaryAnd:
		out = fmt.Sprintf("%s && %s", left, right)
	case BinaryOr:
		out = fmt.Sprintf("%s || %s", left, right)
	case BinaryIntersection:
		out = fmt.Sprintf("%s.intersection(%s)", left, right)
	case BinaryUnion:
		out = fmt.Sprintf("%s.union(%s)", left, right)
	case BinaryBitwiseAnd:
		out = fmt.Sprintf("%s & %s", left, right)
	case BinaryBitwiseOr:
		out = fmt.Sprintf("%s | %s", left, right)
	case BinaryBitwiseXor:
		out = fmt.Sprintf("%s ^ %s", left, right)
	case BinaryNotEqual:
		out = fmt.Sprintf("%s !== %s", left, right)
	case BinaryHeterogeneousEqual:
		out = fmt.Sprintf("%s == %s", left, right)
	case BinaryHeterogeneousNotEqual:
		out = fmt.Sprintf("%s != %s", left, right)
	case BinaryLazyAnd:
		out = fmt.Sprintf("%s && %s", left, right)
	case BinaryLazyOr:
		out = fmt.Sprintf("%s || %s", left, right)
	case BinaryAll:
		out = fmt.Sprintf("%s.all(%s)", left, right)
	case BinaryAny:
		out = fmt.Sprintf("%s.any(%s)", left, right)
	case BinaryGet:
		out = fmt.Sprintf("%s.get(%s)", left, right)
	default:
		out = fmt.Sprintf("unknown(%s, %s)", left, right)
	}
	return out
}

type BinaryOpFunc interface {
	Type() BinaryOpType
	Eval(left, right Term, symbols *SymbolTable) (Term, error)
}

type BinaryOpType byte

const (
	BinaryLessThan BinaryOpType = iota
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
	// Datalog v3.1 operators.
	BinaryBitwiseAnd
	BinaryBitwiseOr
	BinaryBitwiseXor
	BinaryNotEqual
	// Datalog v3.3 operators.
	BinaryHeterogeneousEqual
	BinaryHeterogeneousNotEqual
	BinaryLazyAnd
	BinaryLazyOr
	BinaryAll
	BinaryAny
	BinaryGet
)

// LessThan returns true when left is less than right.
// It requires left and right to have the same concrete type
// and only accepts Integer.
type LessThan struct{}

func (LessThan) Type() BinaryOpType {
	return BinaryLessThan
}
func (LessThan) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: LessThan type mismatch: %d != %d", g, w)
	}

	var out Term
	switch left.Type() {
	case TermTypeInteger:
		out = Bool(left.(Integer) < right.(Integer))
	case TermTypeDate:
		out = Bool(left.(Date) < right.(Date))
	default:
		return nil, fmt.Errorf("datalog: unexpected LessThan value type: %d", left.Type())
	}

	return out, nil
}

// LessOrEqual returns true when left is less or equal than right.
// It requires left and right to have the same concrete type
// and only accepts Integer and Date.
type LessOrEqual struct{}

func (LessOrEqual) Type() BinaryOpType {
	return BinaryLessOrEqual
}
func (LessOrEqual) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: LessOrEqual type mismatch: %d != %d", g, w)
	}

	var out Term
	switch left.Type() {
	case TermTypeInteger:
		out = Bool(left.(Integer) <= right.(Integer))
	case TermTypeDate:
		out = Bool(left.(Date) <= right.(Date))
	default:
		return nil, fmt.Errorf("datalog: unexpected LessOrEqual value type: %d", left.Type())
	}

	return out, nil
}

// GreaterThan returns true when left is greater than right.
// It requires left and right to have the same concrete type
// and only accepts Integer.
type GreaterThan struct{}

func (GreaterThan) Type() BinaryOpType {
	return BinaryGreaterThan
}
func (GreaterThan) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: GreaterThan type mismatch: %d != %d", g, w)
	}

	var out Term
	switch left.Type() {
	case TermTypeInteger:
		out = Bool(left.(Integer) > right.(Integer))
	case TermTypeDate:
		out = Bool(left.(Date) > right.(Date))
	default:
		return nil, fmt.Errorf("datalog: unexpected GreaterThan value type: %d", left.Type())
	}

	return out, nil
}

// GreaterOrEqual returns true when left is greater than right.
// It requires left and right to have the same concrete type
// and only accepts Integer and Date.
type GreaterOrEqual struct{}

func (GreaterOrEqual) Type() BinaryOpType {
	return BinaryGreaterOrEqual
}
func (GreaterOrEqual) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: GreaterOrEqual type mismatch: %d != %d", g, w)
	}

	var out Term
	switch left.Type() {
	case TermTypeInteger:
		out = Bool(left.(Integer) >= right.(Integer))
	case TermTypeDate:
		out = Bool(left.(Date) >= right.(Date))
	default:
		return nil, fmt.Errorf("datalog: unexpected GreaterOrEqual value type: %d", left.Type())
	}

	return out, nil
}

// Equal returns true when left and right are equal.
// It requires left and right to have the same concrete type
// and only accepts Integer, Bytes or String.
type Equal struct{}

func (Equal) Type() BinaryOpType {
	return BinaryEqual
}
func (Equal) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: Equal type mismatch: %d != %d", g, w)
	}

	switch left.Type() {
	case TermTypeInteger:
	case TermTypeBytes:
	case TermTypeString:
	case TermTypeDate:
	case TermTypeBool:
	case TermTypeSet:
	case TermTypeNull:
	case TermTypeArray:
	case TermTypeMap:

	default:
		return nil, fmt.Errorf("datalog: unexpected Equal value type: %d", left.Type())
	}

	return Bool(left.Equal(right)), nil
}

// NotEqual is the negation of Equal, with the same type requirements.
type NotEqual struct{}

func (NotEqual) Type() BinaryOpType {
	return BinaryNotEqual
}
func (NotEqual) Eval(left Term, right Term, symbols *SymbolTable) (Term, error) {
	equal, err := Equal{}.Eval(left, right, symbols)
	if err != nil {
		return nil, err
	}
	return Bool(!equal.(Bool)), nil
}

// HeterogeneousEqual is == since datalog v3.3: values of different types
// are not equal instead of being a type error. Equal (===) keeps the strict
// behaviour.
type HeterogeneousEqual struct{}

func (HeterogeneousEqual) Type() BinaryOpType {
	return BinaryHeterogeneousEqual
}
func (HeterogeneousEqual) Eval(left Term, right Term, symbols *SymbolTable) (Term, error) {
	if left.Type() != right.Type() {
		return Bool(false), nil
	}
	return Equal{}.Eval(left, right, symbols)
}

// HeterogeneousNotEqual is != since datalog v3.3, the negation of
// HeterogeneousEqual.
type HeterogeneousNotEqual struct{}

func (HeterogeneousNotEqual) Type() BinaryOpType {
	return BinaryHeterogeneousNotEqual
}
func (HeterogeneousNotEqual) Eval(left Term, right Term, symbols *SymbolTable) (Term, error) {
	if left.Type() != right.Type() {
		return Bool(true), nil
	}
	return NotEqual{}.Eval(left, right, symbols)
}

// Contains returns true when the right value exists in the left Set.
// The right value must be an Integer, Bytes, String or Symbol.
// The left value must be a Set, containing elements of right type.
type Contains struct{}

func (Contains) Type() BinaryOpType {
	return BinaryContains
}
func (Contains) Eval(left Term, right Term, symbols *SymbolTable) (Term, error) {
	sleft, ok := left.(String)
	if ok {
		sright, ok := right.(String)
		if !ok {
			return nil, fmt.Errorf("datalog: Contains requires right value to be a String, got %T", right)
		}

		return Bool(strings.Contains(symbols.Str(sleft), symbols.Str(sright))), nil
	}

	// An array contains an element, a map contains a key.
	switch left := left.(type) {
	case Array:
		return Bool(left.contains(right)), nil
	case Map:
		return Bool(IsMapKey(right) && left.Get(right) != nil), nil
	}

	switch right.Type() {
	case TermTypeInteger:
	case TermTypeBytes:
	case TermTypeString:
	case TermTypeDate:
	case TermTypeBool:
	case TermTypeSet:

	default:
		return nil, fmt.Errorf("datalog: unexpected Contains right value type: %d", right.Type())
	}

	set, ok := left.(Set)
	if !ok {
		return nil, errors.New("datalog: Contains left value must be a Set")
	}

	rhsset, ok := right.(Set)

	if ok {
		for _, rhselt := range rhsset {
			rhsinlhs := false
			for _, lhselt := range set {
				if lhselt.Equal(rhselt) {
					rhsinlhs = true
				}
			}
			if !rhsinlhs {
				return Bool(false), nil
			}
		}
		return Bool(true), nil
	}

	if slices.ContainsFunc(set, right.Equal) {
		return Bool(true), nil
	}

	return Bool(false), nil
}

// Intersection returns the intersection of two sets
type Intersection struct{}

func (Intersection) Type() BinaryOpType {
	return BinaryIntersection
}
func (Intersection) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	set, ok := left.(Set)
	if !ok {
		return nil, errors.New("datalog: Intersection left value must be a Set")
	}

	set2, ok := right.(Set)
	if !ok {
		return nil, errors.New("datalog: Intersection rightt value must be a Set")
	}

	return set.Intersect(set2), nil
}

// Intersection returns the intersection of two sets
type Union struct{}

func (Union) Type() BinaryOpType {
	return BinaryUnion
}
func (Union) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	set, ok := left.(Set)
	if !ok {
		return nil, errors.New("datalog: Union left value must be a Set")
	}

	set2, ok := right.(Set)
	if !ok {
		return nil, errors.New("datalog: Union rightt value must be a Set")
	}

	return set.Union(set2), nil
}

// Prefix returns true when the left string starts with the right string.
// left and right must be String.
type Prefix struct{}

func (Prefix) Type() BinaryOpType {
	return BinaryPrefix
}
func (Prefix) Eval(left Term, right Term, symbols *SymbolTable) (Term, error) {
	if aleft, ok := left.(Array); ok {
		aright, ok := right.(Array)
		if !ok {
			return nil, fmt.Errorf("datalog: Prefix requires right value to be an Array, got %T", right)
		}
		return Bool(aleft.HasPrefix(aright)), nil
	}
	sleft, ok := left.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Prefix requires left value to be a String, got %T", left)
	}
	sright, ok := right.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Prefix requires right value to be a String, got %T", right)
	}

	return Bool(strings.HasPrefix(symbols.Str(sleft), symbols.Str(sright))), nil
}

// Suffix returns true when the left string ends with the right string.
// left and right must be String.
type Suffix struct{}

func (Suffix) Type() BinaryOpType {
	return BinarySuffix
}
func (Suffix) Eval(left Term, right Term, symbols *SymbolTable) (Term, error) {
	if aleft, ok := left.(Array); ok {
		aright, ok := right.(Array)
		if !ok {
			return nil, fmt.Errorf("datalog: Suffix requires right value to be an Array, got %T", right)
		}
		return Bool(aleft.HasSuffix(aright)), nil
	}
	sleft, ok := left.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Suffix requires left value to be a String, got %T", left)
	}
	sright, ok := right.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Suffix requires right value to be a String, got %T", right)
	}

	return Bool(strings.HasSuffix(symbols.Str(sleft), symbols.Str(sright))), nil
}

// Regex returns true when the right string is a regexp and left matches against it.
// left and right must be String.
type Regex struct{}

func (Regex) Type() BinaryOpType {
	return BinaryRegex
}
func (Regex) Eval(left Term, right Term, symbols *SymbolTable) (Term, error) {
	sleft, ok := left.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Regex requires left value to be a String, got %T", left)
	}
	sright, ok := right.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Regex requires right value to be a String, got %T", right)
	}

	re, err := regexp.Compile(symbols.Str(sright))
	if err != nil {
		return nil, fmt.Errorf("datalog: invalid regex: %q: %v", right, err)
	}
	return Bool(re.Match([]byte(symbols.Str(sleft)))), nil
}

// Add performs the addition of left + right and returns the result.
// It requires left and right to be Integer.
type Add struct{}

func (Add) Type() BinaryOpType {
	return BinaryAdd
}
func (Add) Eval(left Term, right Term, symbols *SymbolTable) (Term, error) {
	sleft, ok := left.(String)
	if ok {
		sright, ok := right.(String)
		if !ok {
			return nil, fmt.Errorf("datalog: Add requires right value to be a String, got %T", right)
		}

		s := symbols.Insert(symbols.Str(sleft) + symbols.Str(sright))
		return s, nil
	}

	ileft, ok := left.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Add requires left value to be an Integer, got %T", left)
	}
	iright, ok := right.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Add requires right value to be an Integer, got %T", right)
	}

	bleft := big.NewInt(int64(ileft))
	bright := big.NewInt(int64(iright))
	res := big.NewInt(0)
	res.Add(bleft, bright)

	if !res.IsInt64() {
		return nil, ErrInt64Overflow
	}
	return Integer(res.Int64()), nil
}

// Sub performs the substraction of left - right and returns the result.
// It requires left and right to be Integer.
type Sub struct{}

func (Sub) Type() BinaryOpType {
	return BinarySub
}
func (Sub) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	ileft, ok := left.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Sub requires left value to be an Integer, got %T", left)
	}
	iright, ok := right.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Sub requires right value to be an Integer, got %T", right)
	}

	bleft := big.NewInt(int64(ileft))
	bright := big.NewInt(int64(iright))
	res := big.NewInt(0)
	res.Sub(bleft, bright)

	if !res.IsInt64() {
		return nil, ErrInt64Overflow
	}
	return Integer(res.Int64()), nil
}

// Mul performs the multiplication of left * right and returns the result.
// It requires left and right to be Integer.
type Mul struct{}

func (Mul) Type() BinaryOpType {
	return BinaryMul
}
func (Mul) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	ileft, ok := left.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Mul requires left value to be an Integer, got %T", left)
	}
	iright, ok := right.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Mul requires right value to be an Integer, got %T", right)
	}

	bleft := big.NewInt(int64(ileft))
	bright := big.NewInt(int64(iright))
	res := big.NewInt(0)
	res.Mul(bleft, bright)

	if !res.IsInt64() {
		return nil, ErrInt64Overflow
	}

	return Integer(res.Int64()), nil
}

// Div performs the division of left / right and returns the result.
// It requires left and right to be Integer.
type Div struct{}

func (Div) Type() BinaryOpType {
	return BinaryDiv
}
func (Div) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	ileft, ok := left.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Div requires left value to be an Integer, got %T", left)
	}
	iright, ok := right.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Div requires right value to be an Integer, got %T", right)
	}

	if iright == 0 {
		return nil, ErrExprDivByZero
	}

	return Integer(ileft / iright), nil
}

// LazyAnd is && since datalog v3.3: the right side is a closure, evaluated
// only when the left side is true.
type LazyAnd struct{}

func (LazyAnd) Type() BinaryOpType {
	return BinaryLazyAnd
}
func (LazyAnd) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	return nil, errors.New("datalog: && requires a closure as right value")
}
func (LazyAnd) EvalClosure(left Term, closure Closure, values map[Variable]*Term, symbols *SymbolTable) (Term, error) {
	b, ok := left.(Bool)
	if !ok {
		return nil, fmt.Errorf("datalog: && requires left value to be a Bool, got %T", left)
	}
	if len(closure.Params) != 0 {
		return nil, errors.New("datalog: && takes a closure without parameters")
	}
	if !b {
		return Bool(false), nil
	}
	return closure.Body.Evaluate(values, symbols)
}

// LazyOr is || since datalog v3.3: the right side is a closure, evaluated
// only when the left side is false.
type LazyOr struct{}

func (LazyOr) Type() BinaryOpType {
	return BinaryLazyOr
}
func (LazyOr) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	return nil, errors.New("datalog: || requires a closure as right value")
}
func (LazyOr) EvalClosure(left Term, closure Closure, values map[Variable]*Term, symbols *SymbolTable) (Term, error) {
	b, ok := left.(Bool)
	if !ok {
		return nil, fmt.Errorf("datalog: || requires left value to be a Bool, got %T", left)
	}
	if len(closure.Params) != 0 {
		return nil, errors.New("datalog: || takes a closure without parameters")
	}
	if b {
		return Bool(true), nil
	}
	return closure.Body.Evaluate(values, symbols)
}

// All is .all($x -> ...): true when the closure holds for every element of
// the left set.
type All struct{}

func (All) Type() BinaryOpType {
	return BinaryAll
}
func (All) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	return nil, errors.New("datalog: .all() requires a closure")
}
func (All) EvalClosure(left Term, closure Closure, values map[Variable]*Term, symbols *SymbolTable) (Term, error) {
	return forEachElement("all", left, closure, values, symbols, func(res Bool) (Term, bool) {
		if !res {
			return Bool(false), true
		}
		return nil, false
	}, Bool(true))
}

// Any is .any($x -> ...): true when the closure holds for one element of
// the left set.
type Any struct{}

func (Any) Type() BinaryOpType {
	return BinaryAny
}
func (Any) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	return nil, errors.New("datalog: .any() requires a closure")
}
func (Any) EvalClosure(left Term, closure Closure, values map[Variable]*Term, symbols *SymbolTable) (Term, error) {
	return forEachElement("any", left, closure, values, symbols, func(res Bool) (Term, bool) {
		if res {
			return Bool(true), true
		}
		return nil, false
	}, Bool(false))
}

// forEachElement evaluates the closure on each element of the collection,
// stopping when decide returns a result; otherwise the result is exhausted.
func forEachElement(name string, collection Term, closure Closure, values map[Variable]*Term, symbols *SymbolTable, decide func(Bool) (Term, bool), exhausted Term) (Term, error) {
	if len(closure.Params) != 1 {
		return nil, fmt.Errorf("datalog: .%s() takes a closure with one parameter", name)
	}
	elements, err := collectionElements(collection)
	if err != nil {
		return nil, fmt.Errorf("datalog: .%s(): %w", name, err)
	}
	param := closure.Params[0]
	for _, element := range elements {
		element := element
		values[param] = &element
		res, err := closure.Body.Evaluate(values, symbols)
		delete(values, param)
		if err != nil {
			return nil, err
		}
		b, ok := res.(Bool)
		if !ok {
			return nil, fmt.Errorf("datalog: .%s() closure must return a Bool, got %T", name, res)
		}
		if out, done := decide(b); done {
			return out, nil
		}
	}
	return exhausted, nil
}

// collectionElements lists the elements a closure iterates over: the
// elements of a set or an array, or [key, value] arrays for a map.
func collectionElements(t Term) ([]Term, error) {
	switch t := t.(type) {
	case Set:
		return t, nil
	case Array:
		return t, nil
	case Map:
		elements := make([]Term, len(t))
		for i, e := range t {
			elements[i] = Array{e.Key, e.Value}
		}
		return elements, nil
	default:
		return nil, fmt.Errorf("requires a Set, an Array or a Map, got %T", t)
	}
}

// Get is .get(): the element of an array at an index, or the value of a map
// for a key; null when there is none.
type Get struct{}

func (Get) Type() BinaryOpType {
	return BinaryGet
}
func (Get) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	switch left := left.(type) {
	case Array:
		index, ok := right.(Integer)
		if !ok {
			return nil, fmt.Errorf("datalog: Get on an Array requires an Integer index, got %T", right)
		}
		if index < 0 || int64(index) >= int64(len(left)) {
			return Null{}, nil
		}
		return left[index], nil
	case Map:
		if !IsMapKey(right) {
			return nil, fmt.Errorf("datalog: Get on a Map requires an Integer or String key, got %T", right)
		}
		if v := left.Get(right); v != nil {
			return v, nil
		}
		return Null{}, nil
	default:
		return nil, fmt.Errorf("datalog: Get requires left value to be an Array or a Map, got %T", left)
	}
}

// And performs a logical AND between left and right and returns a Bool.
// It requires left and right to be Bool.
type And struct{}

func (And) Type() BinaryOpType {
	return BinaryAnd
}
func (And) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	bleft, ok := left.(Bool)
	if !ok {
		return nil, fmt.Errorf("datalog: And requires left value to be a Bool, got %T", left)
	}
	bright, ok := right.(Bool)
	if !ok {
		return nil, fmt.Errorf("datalog: And requires right value to be a Bool, got %T", right)
	}

	return Bool(bleft && bright), nil
}

// BitwiseAnd, BitwiseOr and BitwiseXor operate on two Integers.
type BitwiseAnd struct{}

func (BitwiseAnd) Type() BinaryOpType {
	return BinaryBitwiseAnd
}
func (BitwiseAnd) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	l, r, err := integerOperands("BitwiseAnd", left, right)
	if err != nil {
		return nil, err
	}
	return l & r, nil
}

type BitwiseOr struct{}

func (BitwiseOr) Type() BinaryOpType {
	return BinaryBitwiseOr
}
func (BitwiseOr) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	l, r, err := integerOperands("BitwiseOr", left, right)
	if err != nil {
		return nil, err
	}
	return l | r, nil
}

type BitwiseXor struct{}

func (BitwiseXor) Type() BinaryOpType {
	return BinaryBitwiseXor
}
func (BitwiseXor) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	l, r, err := integerOperands("BitwiseXor", left, right)
	if err != nil {
		return nil, err
	}
	return l ^ r, nil
}

func integerOperands(op string, left, right Term) (Integer, Integer, error) {
	l, ok := left.(Integer)
	if !ok {
		return 0, 0, fmt.Errorf("datalog: %s requires left value to be an Integer, got %T", op, left)
	}
	r, ok := right.(Integer)
	if !ok {
		return 0, 0, fmt.Errorf("datalog: %s requires right value to be an Integer, got %T", op, right)
	}
	return l, r, nil
}

// Or performs a logical OR between left and right and returns a Bool.
// It requires left and right to be Bool.
type Or struct{}

func (Or) Type() BinaryOpType {
	return BinaryOr
}
func (Or) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	bleft, ok := left.(Bool)
	if !ok {
		return nil, fmt.Errorf("datalog: Or requires left value to be a Bool, got %T", left)
	}
	bright, ok := right.(Bool)
	if !ok {
		return nil, fmt.Errorf("datalog: Or requires right value to be a Bool, got %T", right)
	}

	return Bool(bleft || bright), nil
}

// stackElem is a term, or a closure waiting for the operator that consumes it.
type stackElem struct {
	term    Term
	closure *Closure
}

type stack []stackElem

func (s *stack) Push(v stackElem) error {
	if len(*s) >= maxStackSize {
		return errors.New("stack overflow")
	}

	*s = append(*s, v)

	return nil
}

func (s *stack) Pop() (stackElem, error) {
	if len(*s) == 0 {
		return stackElem{}, errors.New("cannot pop from empty stack")
	}

	e := (*s)[len(*s)-1]
	*s = (*s)[:len(*s)-1]

	return e, nil
}

// PopTerm pops an element that must be a term.
func (s *stack) PopTerm() (Term, error) {
	e, err := s.Pop()
	if err != nil {
		return nil, err
	}
	if e.closure != nil {
		return nil, errors.New("closure where a value was expected")
	}
	return e.term, nil
}

type stringstack []string

func (s *stringstack) Push(v string) error {
	if len(*s) >= maxStackSize {
		return errors.New("stack overflow")
	}

	*s = append(*s, v)

	return nil
}

func (s *stringstack) Pop() (string, error) {
	if len(*s) == 0 {
		return "", errors.New("cannot pop from empty stack")
	}

	e := (*s)[len(*s)-1]
	*s = (*s)[:len(*s)-1]

	return e, nil
}
