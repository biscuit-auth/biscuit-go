package biscuit

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/flynn/biscuit-go/datalog"
)

const SymbolAuthority = Symbol("authority")

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
	caveats []datalog.Caveat
	context string
}

func (b *Block) String(symbols *datalog.SymbolTable) string {
	debug := &datalog.SymbolDebugger{
		SymbolTable: symbols,
	}
	rules := make([]string, len(b.rules))
	for i, r := range b.rules {
		rules[i] = debug.Rule(r)
	}

	caveats := make([]string, len(b.caveats))
	for i, c := range b.caveats {
		caveats[i] = debug.Caveat(c)
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
	atoms := make([]Atom, 0, len(p.IDs))
	for _, id := range p.IDs {
		a, err := fromDatalogID(symbols, id)
		if err != nil {
			return nil, err
		}
		atoms = append(atoms, a)
	}

	return &Predicate{
		Name: symbols.Str(p.Name),
		IDs:  atoms,
	}, nil
}

func fromDatalogID(symbols *datalog.SymbolTable, id datalog.ID) (Atom, error) {
	var a Atom
	switch id.Type() {
	case datalog.IDTypeSymbol:
		a = Symbol(symbols.Str(id.(datalog.Symbol)))
	case datalog.IDTypeVariable:
		a = Variable(id.(datalog.Variable))
	case datalog.IDTypeInteger:
		a = Integer(id.(datalog.Integer))
	case datalog.IDTypeString:
		a = String(id.(datalog.String))
	case datalog.IDTypeDate:
		a = Date(time.Unix(int64(id.(datalog.Date)), 0))
	case datalog.IDTypeBytes:
		a = Bytes(id.(datalog.Bytes))
	case datalog.IDTypeList:
		listIDs := id.(datalog.List)
		list := make(List, 0, len(listIDs))
		for _, i := range listIDs {
			listAtom, err := fromDatalogID(symbols, i)
			if err != nil {
				return nil, err
			}
			list = append(list, listAtom)
		}
		a = list
	default:
		return nil, fmt.Errorf("unsupported atom type: %v", a.Type())
	}

	return a, nil
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

type Caveat struct {
	Queries []Rule
}

func (c Caveat) convert(symbols *datalog.SymbolTable) datalog.Caveat {
	queries := make([]datalog.Rule, len(c.Queries))
	for i, q := range c.Queries {
		queries[i] = q.convert(symbols)
	}

	return datalog.Caveat{
		Queries: queries,
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

type Checker interface {
	convert(symbols *datalog.SymbolTable) datalog.Checker
}

type IntegerComparisonChecker struct {
	Comparison datalog.IntegerComparison
	Integer    Integer
}

func (c IntegerComparisonChecker) convert(symbols *datalog.SymbolTable) datalog.Checker {
	return datalog.IntegerComparisonChecker{
		Comparison: c.Comparison,
		Integer:    c.Integer.convert(symbols).(datalog.Integer),
	}
}

type IntegerInChecker struct {
	Set map[Integer]struct{}
	Not bool
}

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

type StringRegexpChecker regexp.Regexp

func (c StringRegexpChecker) convert(symbols *datalog.SymbolTable) datalog.Checker {
	re := datalog.StringRegexpChecker(c)
	return &re
}

type DateComparison byte

type DateComparisonChecker struct {
	Comparison datalog.DateComparison
	Date       Date
}

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

type BytesComparisonChecker struct {
	Comparison datalog.BytesComparison
	Bytes      Bytes
}

func (c BytesComparisonChecker) convert(symbols *datalog.SymbolTable) datalog.Checker {
	return datalog.BytesComparisonChecker{
		Comparison: c.Comparison,
		Bytes:      c.Bytes.convert(symbols).(datalog.Bytes),
	}
}

type BytesInChecker struct {
	Set map[string]struct{}
	Not bool
}

func (c BytesInChecker) convert(symbols *datalog.SymbolTable) datalog.Checker {
	return datalog.BytesInChecker{
		Set: c.Set,
		Not: c.Not,
	}
}

type ListContainsChecker struct {
	Values []Atom
	Any    bool
}

func (c ListContainsChecker) convert(symbols *datalog.SymbolTable) datalog.Checker {
	values := make([]datalog.ID, 0, len(c.Values))
	for _, v := range c.Values {
		values = append(values, v.convert(symbols))
	}

	return datalog.ListContainsChecker{
		Values: values,
		Any:    c.Any,
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
func (p Predicate) String() string {
	atoms := make([]string, 0, len(p.IDs))
	for _, a := range p.IDs {
		atoms = append(atoms, a.String())
	}
	return fmt.Sprintf("%s(%s)", p.Name, strings.Join(atoms, ", "))
}

type AtomType byte

const (
	AtomTypeSymbol AtomType = iota
	AtomTypeVariable
	AtomTypeInteger
	AtomTypeString
	AtomTypeDate
	AtomTypeBytes
	AtomTypeList
)

type Atom interface {
	Type() AtomType
	String() string
	convert(symbols *datalog.SymbolTable) datalog.ID
}

type Symbol string

func (a Symbol) Type() AtomType { return AtomTypeSymbol }
func (a Symbol) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Symbol(symbols.Insert(string(a)))
}
func (a Symbol) String() string { return fmt.Sprintf("#%s", string(a)) }

type Variable uint32

func (a Variable) Type() AtomType { return AtomTypeVariable }
func (a Variable) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Variable(a)
}
func (a Variable) String() string { return fmt.Sprintf("$%d", a) }

type Integer int64

func (a Integer) Type() AtomType { return AtomTypeInteger }
func (a Integer) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Integer(a)
}
func (a Integer) String() string { return fmt.Sprintf("%d", a) }

type String string

func (a String) Type() AtomType { return AtomTypeString }
func (a String) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.String(a)
}
func (a String) String() string { return fmt.Sprintf("%q", string(a)) }

type Date time.Time

func (a Date) Type() AtomType { return AtomTypeDate }
func (a Date) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Date(time.Time(a).Unix())
}
func (a Date) String() string { return time.Time(a).Format(time.RFC3339) }

type Bytes []byte

func (a Bytes) Type() AtomType { return AtomTypeBytes }
func (a Bytes) convert(symbols *datalog.SymbolTable) datalog.ID {
	return datalog.Bytes(a)
}
func (a Bytes) String() string { return fmt.Sprintf("hex:%s", hex.EncodeToString(a)) }

type List []Atom

func (a List) Type() AtomType { return AtomTypeList }
func (a List) convert(symbols *datalog.SymbolTable) datalog.ID {
	datalogList := make(datalog.List, 0, len(a))
	for _, e := range a {
		datalogList = append(datalogList, e.convert(symbols))
	}
	return datalogList
}
func (a List) String() string {
	elts := make([]string, 0, len(a))
	for _, e := range a {
		elts = append(elts, e.String())
	}

	return fmt.Sprintf("[%s]", strings.Join(elts, ", "))
}
