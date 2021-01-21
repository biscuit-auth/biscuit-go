package datalog

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// maxStackSize defines the maximum number of elements that can be  stored on the stack.
// Trying to store more than maxStackSize elements returns an error
const maxStackSize = 1000

type Expression []Op

func (e *Expression) Evaluate(values map[Variable]*ID) (ID, error) {
	s := &stack{}

	for _, op := range *e {
		switch op.Type() {
		case OpTypeValue:
			id := op.(Value).ID
			switch id.Type() {
			case IDTypeVariable:
				var ok bool
				idptr, ok := values[id.(Variable)]
				if !ok {
					return nil, fmt.Errorf("datalog: expressions: unknown variable %d", id.(Variable))
				}
				id = *idptr
			}
			s.Push(id)
		case OpTypeUnary:
			v, err := s.Pop()
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: failed to pop unary value: %v", err)
			}

			res, err := op.(UnaryOp).Eval(v)
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: unary eval failed: %v", err)
			}
			s.Push(res)
		case OpTypeBinary:
			right, err := s.Pop()
			if err != nil {
				return nil, fmt.Errorf("datalog: expressiosn: failed to pop binary right value: %v", err)
			}
			left, err := s.Pop()
			if err != nil {
				return nil, fmt.Errorf("datalog: expressiosn: failed to pop binary left value: %v", err)
			}

			res, err := op.(BinaryOp).Eval(left, right)
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: binary eval failed: %v", err)
			}
			s.Push(res)
		default:
			return nil, fmt.Errorf("datalog: expressions: unsupported Op: %v", op.Type())
		}
	}

	// after processing all operations, there must be a single value left in the stack
	if len(*s) != 1 {
		return nil, fmt.Errorf("datalog: expressions: invalid resulting stack: %#v", *s)
	}

	return s.Pop()
}

func (e *Expression) String() string {
	return "TODO"
}

type OpType byte

const (
	OpTypeValue OpType = iota
	OpTypeUnary
	OpTypeBinary
)

type Op interface {
	Type() OpType
}

type Value struct {
	ID ID
}

func (v Value) Type() OpType {
	return OpTypeValue
}

type UnaryOp struct {
	Eval func(value ID) (ID, error)
}

func (UnaryOp) Type() OpType {
	return OpTypeUnary
}

// Negate returns the negation of value
// for an integer 42, returns -42
// for a boolean true, return false
func Negate(value ID) (ID, error) {
	var out ID
	switch value.Type() {
	case IDTypeInteger:
		out = value.(Integer) * -1
	case IDTypeBool:
		out = !value.(Bool)
	default:
		return nil, fmt.Errorf("datalog: unexpected Negate value type: %d", value.Type())
	}

	return out, nil
}

type BinaryOp struct {
	Eval func(left, right ID) (ID, error)
}

func (BinaryOp) Type() OpType {
	return OpTypeBinary
}

// LessThan returns true when left is less than right.
// It requires left and right to have the same concret type
// and only accept Integer
func LessThan(left ID, right ID) (ID, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: LessThan type mismatch: %d != %d", g, w)
	}

	var out ID
	switch left.Type() {
	case IDTypeInteger:
		out = Bool(left.(Integer) < right.(Integer))
	default:
		return nil, fmt.Errorf("datalog: unexpected LessThan value type: %d", left.Type())
	}

	return out, nil
}

// LessOrEqual returns true when left is less or equal right.
// It requires left and right to have the same concret type
// and only accept Integer and Date
func LessOrEqual(left ID, right ID) (ID, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: LessOrEqual type mismatch: %d != %d", g, w)
	}

	var out ID
	switch left.Type() {
	case IDTypeInteger:
		out = Bool(left.(Integer) <= right.(Integer))
	case IDTypeDate:
		out = Bool(left.(Date) <= right.(Date))
	default:
		return nil, fmt.Errorf("datalog: unexpected LessOrEqual value type: %d", left.Type())
	}

	return out, nil
}

// GreaterThan returns true when left is greater than right.
// It requires left and right to have the same concret type
// and only accept Integer
func GreaterThan(left ID, right ID) (ID, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: GreaterThan type mismatch: %d != %d", g, w)
	}

	var out ID
	switch left.Type() {
	case IDTypeInteger:
		out = Bool(left.(Integer) > right.(Integer))
	default:
		return nil, fmt.Errorf("datalog: unexpected GreaterThan value type: %d", left.Type())
	}

	return out, nil
}

// GreaterOrEqual returns true when left is greater than right.
// It requires left and right to have the same concret type
// and only accept Integer and Date
func GreaterOrEqual(left ID, right ID) (ID, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: GreaterOrEqual type mismatch: %d != %d", g, w)
	}

	var out ID
	switch left.Type() {
	case IDTypeInteger:
		out = Bool(left.(Integer) >= right.(Integer))
	case IDTypeDate:
		out = Bool(left.(Date) >= right.(Date))
	default:
		return nil, fmt.Errorf("datalog: unexpected GreaterOrEqual value type: %d", left.Type())
	}

	return out, nil
}

// Equal returns true when left and right are equal.
// It requires left and right to have the same concret type
// and only accept Integer, Bytes or String
func Equal(left ID, right ID) (ID, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: Equal type mismatch: %d != %d", g, w)
	}

	switch left.Type() {
	case IDTypeInteger:
	case IDTypeBytes:
	case IDTypeString:
	default:
		return nil, fmt.Errorf("datalog: unexpected Equal value type: %d", left.Type())
	}

	return Bool(left.Equal(right)), nil
}

// In returns true when left exists in the right Set.
// left value must be an Integer, Bytes, String or Symbol
// right value must be a Set, containing elements of left type.
func In(left ID, right ID) (ID, error) {
	switch left.Type() {
	case IDTypeInteger:
	case IDTypeBytes:
	case IDTypeString:
	case IDTypeSymbol:
	default:
		return nil, fmt.Errorf("datalog: unexpected In left value type: %d", left.Type())
	}

	set, ok := right.(Set)
	if !ok {
		return nil, errors.New("datalog: In right value must be a Set")
	}

	for _, elt := range set {
		if g, w := elt.Type(), left.Type(); g != w {
			return nil, fmt.Errorf("datalog: unexpected In set element type: got %d, want %d", g, w)
		}
		if left.Equal(elt) {
			return Bool(true), nil
		}
	}

	return Bool(false), nil
}

// NotIn returns true when left does not exists in the right Set.
// left value must be an Integer, Bytes, String or Symbol
// right value must be a Set, containing elements of left type.
func NotIn(left ID, right ID) (ID, error) {
	switch left.Type() {
	case IDTypeInteger:
	case IDTypeBytes:
	case IDTypeString:
	case IDTypeSymbol:
	default:
		return nil, fmt.Errorf("datalog: unexpected NotIn left value type: %d", left.Type())
	}

	set, ok := right.(Set)
	if !ok {
		return nil, errors.New("datalog: NotIn right value must be a Set")
	}

	for _, elt := range set {
		if g, w := elt.Type(), left.Type(); g != w {
			return nil, fmt.Errorf("datalog: unexpected NotIn set element type: got %d, want %d", g, w)
		}
		if left.Equal(elt) {
			return Bool(false), nil
		}
	}

	return Bool(true), nil
}

// Prefix returns true when left string starts with right string
// left and right must be String
func Prefix(left ID, right ID) (ID, error) {
	sleft, ok := left.(String)
	if !ok {
		return nil, errors.New("datalog: Prefix requires left value to be a String")
	}
	sright, ok := right.(String)
	if !ok {
		return nil, errors.New("datalog: Prefix requires right value to be a String")
	}

	return Bool(strings.HasPrefix(string(sleft), string(sright))), nil
}

// Suffix returns true when left string ends with right string
// left and right must be String
func Suffix(left ID, right ID) (ID, error) {
	sleft, ok := left.(String)
	if !ok {
		return nil, errors.New("datalog: Suffix requires left value to be a String")
	}
	sright, ok := right.(String)
	if !ok {
		return nil, errors.New("datalog: Suffix requires right value to be a String")
	}

	return Bool(strings.HasSuffix(string(sleft), string(sright))), nil
}

// Regex returns true when right string is a regexp and left match against it.
// left and right must be String
func Regex(left ID, right ID) (ID, error) {
	sleft, ok := left.(String)
	if !ok {
		return nil, errors.New("datalog: Regex requires left value to be a String")
	}
	sright, ok := right.(String)
	if !ok {
		return nil, errors.New("datalog: Regex requires right value to be a String")
	}

	re, err := regexp.Compile(string(sright))
	if err != nil {
		return nil, fmt.Errorf("datalog: invalid regex: %q: %v", right, err)
	}
	return Bool(re.Match([]byte(sleft))), nil
}

// Add performs the addition of left + right and returns the result
// It requires left and right to be Integer
func Add(left ID, right ID) (ID, error) {
	ileft, ok := left.(Integer)
	if !ok {
		return nil, errors.New("datalog: Add requires left value to be an Integer")
	}
	iright, ok := right.(Integer)
	if !ok {
		return nil, errors.New("datalog: Add requires right value to be an Integer")
	}

	return Integer(ileft + iright), nil
}

// And performs a logical AND between left and right and returns a Bool
// It requires left and right to be Bool
func And(left ID, right ID) (ID, error) {
	bleft, ok := left.(Bool)
	if !ok {
		return nil, errors.New("datalog: Add requires left value to be a Bool")
	}
	bright, ok := right.(Bool)
	if !ok {
		return nil, errors.New("datalog: Add requires right value to be a Bool")
	}

	return Bool(bleft && bright), nil
}

type stack []ID

func (s *stack) Push(v ID) error {
	if len(*s) >= maxStackSize {
		return errors.New("stack overflow")
	}

	*s = append(*s, v)

	return nil
}

func (s *stack) Pop() (ID, error) {
	if len(*s) == 0 {
		return nil, errors.New("cannot pop from empty stack")
	}

	e := (*s)[len(*s)-1]
	*s = (*s)[:len(*s)-1]

	return e, nil
}
