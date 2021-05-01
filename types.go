package biscuit

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/flynn/biscuit-go/datalog"
)

const SymbolAuthority = Symbol("authority")

const MaxSchemaVersion uint32 = 1

// defaultSymbolTable predefines some symbols available in every implementation, to avoid
// transmitting them with every token
var defaultSymbolTable = &datalog.SymbolTable{
	"authority",
	"ambient",
	"resource",
	"operation",
	"right",
	"current_time",
	"revocation_id",
}

type Block struct {
	index   uint32
	symbols *datalog.SymbolTable
	facts   *datalog.FactSet
	rules   []datalog.Rule
	checks  []datalog.Check
	context string
	version uint32
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

	return fmt.Sprintf(`Block[%d] {
		symbols: %+q
		context: %q
		facts: %v
		rules: %v
		checks: %v
		version: %d
	}`,
		b.index,
		*b.symbols,
		b.context,
		debug.FactSet(b.facts),
		rules,
		checks,
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
	terms := make([]Term, 0, len(p.IDs))
	for _, id := range p.IDs {
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

func fromDatalogID(symbols *datalog.SymbolTable, id datalog.ID) (Term, error) {
	var a Term
	switch id.Type() {
	case datalog.IDTypeSymbol:
		a = Symbol(symbols.Str(id.(datalog.Symbol)))
	case datalog.IDTypeVariable:
		a = Variable(symbols.Str(datalog.Symbol(id.(datalog.Variable))))
	case datalog.IDTypeInteger:
		a = Integer(id.(datalog.Integer))
	case datalog.IDTypeString:
		a = String(id.(datalog.String))
	case datalog.IDTypeDate:
		a = Date(time.Unix(int64(id.(datalog.Date)), 0))
	case datalog.IDTypeBytes:
		a = Bytes(id.(datalog.Bytes))
	case datalog.IDTypeBool:
		a = Bool(id.(datalog.Bool))
	case datalog.IDTypeSet:
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
	}
}

type Expression []Op

func (e Expression) convert(symbols *datalog.SymbolTable) datalog.Expression {
	expr := make(datalog.Expression, len(e))
	for i, elt := range e {
		expr[i] = elt.convert(symbols)
	}
	return expr
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

type unaryOpType byte

type UnaryOp unaryOpType

const (
	UnaryUndefined UnaryOp = iota
	UnaryNegate
	UnaryParens
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
	default:
		panic(fmt.Sprintf("biscuit: cannot convert invalid unary op type: %v", op))
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
	default:
		panic(fmt.Sprintf("biscuit: cannot convert invalid binary op type: %v", op))
	}
}

type Check struct {
	Queries []Rule
}

func (c Check) convert(symbols *datalog.SymbolTable) datalog.Check {
	queries := make([]datalog.Rule, len(c.Queries))
	for i, q := range c.Queries {
		queries[i] = q.convert(symbols)
	}

	return datalog.Check{
		Queries: queries,
	}
}

type Predicate struct {
	Name string
	IDs  []Term
}

func (p Predicate) convert(symbols *datalog.SymbolTable) datalog.Predicate {
	var ids []datalog.ID
	for _, a := range p.IDs {
		ids = append(ids, a.convert(symbols))
	}

	return datalog.Predicate{
		Name: symbols.Insert(p.Name),
		IDs:  ids,
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
	convert(symbols *datalog.SymbolTable) datalog.ID
}

type Symbol string

func (a Symbol) Type() TermType { return TermTypeSymbol }
func (a Symbol) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Symbol(symbols.Insert(string(a)))
}
func (a Symbol) String() string { return fmt.Sprintf("#%s", string(a)) }

type Variable string

func (a Variable) Type() TermType { return TermTypeVariable }
func (a Variable) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Variable(symbols.Insert(string(a)))
}
func (a Variable) String() string { return fmt.Sprintf("$%s", string(a)) }

type Integer int64

func (a Integer) Type() TermType { return TermTypeInteger }
func (a Integer) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Integer(a)
}
func (a Integer) String() string { return fmt.Sprintf("%d", a) }

type String string

func (a String) Type() TermType { return TermTypeString }
func (a String) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.String(a)
}
func (a String) String() string { return fmt.Sprintf("%q", string(a)) }

type Date time.Time

func (a Date) Type() TermType { return TermTypeDate }
func (a Date) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Date(time.Time(a).Unix())
}
func (a Date) String() string { return time.Time(a).Format(time.RFC3339) }

type Bytes []byte

func (a Bytes) Type() TermType { return TermTypeBytes }
func (a Bytes) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Bytes(a)
}
func (a Bytes) String() string { return fmt.Sprintf("hex:%s", hex.EncodeToString(a)) }

type Bool bool

func (b Bool) Type() TermType { return TermTypeBool }
func (b Bool) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Bool(b)
}
func (b Bool) String() string { return fmt.Sprintf("%t", b) }

type Set []Term

func (a Set) Type() TermType { return TermTypeSet }
func (a Set) convert(symbols *datalog.SymbolTable) datalog.ID {
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
	sort.Strings(elts)
	return fmt.Sprintf("[%s]", strings.Join(elts, ", "))
}
