package biscuit

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/biscuit-auth/biscuit-go/datalog"
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
	caveats []datalog.Caveat
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
		version: %d
	}`,
		b.index,
		*b.symbols,
		b.context,
		debug.FactSet(b.facts),
		rules,
		caveats,
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
	default:
		return nil, fmt.Errorf("unsupported term type: %v", a.Type())
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

func (c Constraint) String() string {
	return c.Checker.String(c.Name)
}

type Checker interface {
	convert(symbols *datalog.SymbolTable) datalog.Checker
	String(name Variable) string
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

func (c IntegerComparisonChecker) String(name Variable) string {
	op := "??"
	switch c.Comparison {
	case datalog.IntegerComparisonEqual:
		op = "=="
	case datalog.IntegerComparisonGT:
		op = ">"
	case datalog.IntegerComparisonGTE:
		op = ">="
	case datalog.IntegerComparisonLT:
		op = "<"
	case datalog.IntegerComparisonLTE:
		op = "<="
	}
	return fmt.Sprintf("%s %s %s", name, op, c.Integer)
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

func (c IntegerInChecker) String(name Variable) string {
	op := "in"
	if c.Not {
		op = "not in"
	}

	set := make([]string, 0, len(c.Set))
	for k := range c.Set {
		set = append(set, k.String())
	}
	sort.Strings(set)
	return fmt.Sprintf("%s %s %s", name, op, strings.Join(set, ", "))
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
func (c StringComparisonChecker) String(name Variable) string {
	out := fmt.Sprintf("%s ?? %s", name, c.Str)
	switch c.Comparison {
	case datalog.StringComparisonEqual:
		out = fmt.Sprintf("%s == %s", name, c.Str)
	case datalog.StringComparisonPrefix:
		out = fmt.Sprintf("prefix(%s, %s)", name, c.Str)
	case datalog.StringComparisonSuffix:
		out = fmt.Sprintf("suffix(%s, %s)", name, c.Str)
	}
	return out
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
func (c StringInChecker) String(name Variable) string {
	op := "in"
	if c.Not {
		op = "not in"
	}
	set := make([]string, 0, len(c.Set))
	for v := range c.Set {
		set = append(set, v.String())
	}
	sort.Strings(set)
	return fmt.Sprintf("%s %s [%s]", name, op, strings.Join(set, ", "))
}

type StringRegexpChecker regexp.Regexp

func (c StringRegexpChecker) convert(symbols *datalog.SymbolTable) datalog.Checker {
	re := datalog.StringRegexpChecker(c)
	return &re
}
func (c StringRegexpChecker) String(name Variable) string {
	r := regexp.Regexp(c)
	return fmt.Sprintf("%s match %s", name, r.String())
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
func (c DateComparisonChecker) String(name Variable) string {
	op := "??"
	switch c.Comparison {
	case datalog.DateComparisonAfter:
		op = ">"
	case datalog.DateComparisonBefore:
		op = "<"
	}
	return fmt.Sprintf("%s %s %s", name, op, c.Date)
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
func (c SymbolInChecker) String(name Variable) string {
	op := "in"
	if c.Not {
		op = "not in"
	}
	set := make([]string, 0, len(c.Set))
	for v := range c.Set {
		set = append(set, v.String())
	}
	sort.Strings(set)
	return fmt.Sprintf("%s %s [%s]", name, op, strings.Join(set, ", "))
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
func (c BytesComparisonChecker) String(name Variable) string {
	op := "??"
	switch c.Comparison {
	case datalog.BytesComparisonEqual:
		op = "=="
	}
	return fmt.Sprintf("%s %s %s", name, op, c.Bytes)
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
func (c BytesInChecker) String(name Variable) string {
	op := "in"
	if c.Not {
		op = "not in"
	}
	set := make([]string, 0, len(c.Set))
	for v := range c.Set {
		set = append(set, fmt.Sprintf("hex:%s", v))
	}
	sort.Strings(set)
	return fmt.Sprintf("%s %s [%s]", name, op, strings.Join(set, ", "))
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
