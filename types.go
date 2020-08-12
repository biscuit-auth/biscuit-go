package biscuit

import (
	"fmt"
	"time"

	"github.com/flynn/biscuit-go/datalog"
)

var SymAuthority = Symbol("authority")

// DefaultSymbolTable predefines some symbols available in every implementation, to avoid
// transmitting them with every token
var DefaultSymbolTable = &datalog.SymbolTable{
	"authority",
	"ambient",
	"resource",
	"operation",
	"right",
	"current_time",
	"revocation_id",
}

type Block struct {
	index   int
	symbols *datalog.SymbolTable
	facts   *datalog.FactSet
	rules   []*datalog.Rule
	caveats []*datalog.Caveat
	context string
}

func (b *Block) Print(symbols *datalog.SymbolTable) string {
	debug := &datalog.SymbolDebugger{
		SymbolTable: symbols,
	}
	rules := make([]string, len(b.rules))
	for i, r := range b.rules {
		rules[i] = debug.Rule(*r)
	}

	caveats := make([]string, len(b.caveats))
	for i, c := range b.caveats {
		caveats[i] = debug.Caveat(*c)
	}

	return fmt.Sprintf(`Block[%d] {
		symbols: %+q
		context: %q
		facts: %v
		rules: %v
		caveats: %v
	}`,
		b.index,
		*b.symbols,
		b.context,
		debug.FactSet(b.facts),
		rules,
		caveats,
	)
}

type Fact struct {
	Predicate
}

func (f Fact) convert(symbols *datalog.SymbolTable) datalog.Fact {
	return datalog.Fact{
		Predicate: f.Predicate.convert(symbols),
	}
}

type Rule struct {
	Head        Predicate
	Body        []Predicate
	Constraints []Constraint
}

func (r Rule) convert(symbols *datalog.SymbolTable) datalog.Rule {
	dlBody := make([]datalog.Predicate, len(r.Body))
	for i, p := range r.Body {
		dlBody[i] = p.convert(symbols)
	}

	dlConstraints := make([]datalog.Constraint, len(r.Constraints))
	for i, c := range r.Constraints {
		dlConstraints[i] = c.convert(symbols)
	}
	return datalog.Rule{
		Head:        r.Head.convert(symbols),
		Body:        dlBody,
		Constraints: dlConstraints,
	}
}

type Constraint struct {
	Name Variable
	Checker
}

func (c Constraint) convert(symbols *datalog.SymbolTable) datalog.Constraint {
	return datalog.Constraint{
		Name:    c.Name.convert(symbols).(datalog.Variable),
		Checker: c.Checker.convert(symbols),
	}
}

type CheckerType byte

const (
	CheckerTypeIntegerComparison CheckerType = iota
	CheckerTypeIntegerIn
	CheckerTypeStringComparison
	CheckerTypeStringIn
	CheckerTypeDateComparison
	CheckerTypeSymbolIn
)

type Checker interface {
	Type() CheckerType
	convert(symbols *datalog.SymbolTable) datalog.Checker
}

type IntegerComparisonChecker struct {
	Comparison datalog.IntegerComparison
	Integer    Integer
}

func (c IntegerComparisonChecker) Type() CheckerType { return CheckerTypeIntegerComparison }
func (c IntegerComparisonChecker) convert(symbols *datalog.SymbolTable) datalog.Checker {
	return &datalog.IntegerComparisonChecker{
		Comparison: c.Comparison,
		Integer:    c.Integer.convert(symbols).(datalog.Integer),
	}
}

type IntegerInChecker struct {
	Set map[Integer]struct{}
	Not bool
}

func (c IntegerInChecker) Type() CheckerType { return CheckerTypeIntegerIn }
func (c IntegerInChecker) convert(symbols *datalog.SymbolTable) datalog.Checker {
	dlSet := make(map[datalog.Integer]struct{}, len(c.Set))
	for i := range c.Set {
		dlSet[i.convert(symbols).(datalog.Integer)] = struct{}{}
	}
	return datalog.IntegerInChecker{
		Set: dlSet,
		Not: c.Not,
	}
}

type StringComparison byte

type StringComparisonChecker struct {
	Comparison datalog.StringComparison
	Str        String
}

func (c StringComparisonChecker) Type() CheckerType { return CheckerTypeStringComparison }
func (c StringComparisonChecker) convert(symbols *datalog.SymbolTable) datalog.Checker {
	return datalog.StringComparisonChecker{
		Comparison: c.Comparison,
		Str:        c.Str.convert(symbols).(datalog.String),
	}
}

type StringInChecker struct {
	Set map[String]struct{}
	Not bool
}

func (c StringInChecker) Type() CheckerType { return CheckerTypeStringIn }
func (c StringInChecker) convert(symbols *datalog.SymbolTable) datalog.Checker {
	dlSet := make(map[datalog.String]struct{}, len(c.Set))
	for i := range c.Set {
		dlSet[i.convert(symbols).(datalog.String)] = struct{}{}
	}
	return datalog.StringInChecker{
		Set: dlSet,
		Not: c.Not,
	}
}

type DateComparison byte

type DateComparisonChecker struct {
	Comparison datalog.DateComparison
	Date       Date
}

func (c DateComparisonChecker) Type() CheckerType { return CheckerTypeDateComparison }
func (c DateComparisonChecker) convert(symbols *datalog.SymbolTable) datalog.Checker {
	return datalog.DateComparisonChecker{
		Comparison: c.Comparison,
		Date:       c.Date.convert(symbols).(datalog.Date),
	}
}

type SymbolInChecker struct {
	Set map[Symbol]struct{}
	Not bool
}

func (c SymbolInChecker) Type() CheckerType { return CheckerTypeSymbolIn }
func (c SymbolInChecker) convert(symbols *datalog.SymbolTable) datalog.Checker {
	dlSet := make(map[datalog.Symbol]struct{}, len(c.Set))
	for i := range c.Set {
		dlSet[i.convert(symbols).(datalog.Symbol)] = struct{}{}
	}
	return datalog.SymbolInChecker{
		Set: dlSet,
		Not: c.Not,
	}
}

type Predicate struct {
	Name string
	IDs  []Atom
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

type AtomType byte

const (
	AtomTypeSymbol AtomType = iota
	AtomTypeVariable
	AtomTypeInteger
	AtomTypeString
	AtomTypeDate
)

const (
	AuthoritySymbol = Symbol("authority")
)

type Atom interface {
	Type() AtomType

	convert(symbols *datalog.SymbolTable) datalog.ID
}

type Symbol string

func (a Symbol) Type() AtomType { return AtomTypeSymbol }
func (a Symbol) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Symbol(symbols.Insert(string(a)))
}

type Variable uint32

func (a Variable) Type() AtomType { return AtomTypeVariable }
func (a Variable) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Variable(a)
}

type Integer int64

func (a Integer) Type() AtomType { return AtomTypeInteger }
func (a Integer) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Integer(a)
}

type String string

func (a String) Type() AtomType { return AtomTypeString }
func (a String) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.String(a)
}

type Date time.Time

func (a Date) Type() AtomType { return AtomTypeDate }
func (a Date) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.String(time.Time(a).UnixNano())
}
