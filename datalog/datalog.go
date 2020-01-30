package datalog

import (
	"regexp"
	"strings"
)

type Matcher interface {
	Match(ID) bool
}

type IDType byte

const (
	IDTypeSymbol IDType = iota
	IDTypeVariable
	IDTypeInteger
	IDTypeString
	IDTypeDate
)

type ID interface {
	Type() IDType
}

type Symbol uint64

func (Symbol) Type() IDType { return IDTypeSymbol }

type Variable uint32

func (Variable) Type() IDType { return IDTypeVariable }

type Integer int64

func (Integer) Type() IDType { return IDTypeInteger }

type String String

func (String) Type() IDType { return IDTypeString }

type Date uint64

func (Date) Type() IDType { return IDTypeDate }

type IntegerComparison byte

const (
	IntegerComparisonEqual IntegerComparison = iota
	IntegerComparisonLT
	IntegerComparisonGT
	IntegerComparisonLTE
	IntegerComparisonGTE
)

type IntegerComparisonMatcher struct {
	Comparison IntegerComparison
	Integer    Integer
}

func (m *IntegerComparisonMatcher) Match(id ID) bool {
	if id.Type() != IDTypeInteger {
		return false
	}
	v := id.(Integer)
	switch m.Comparison {
	case IntegerComparisonEqual:
		return v == m.Integer
	case IntegerComparisonLT:
		return v < m.Integer
	case IntegerComparisonGT:
		return v > m.Integer
	case IntegerComparisonLTE:
		return v <= m.Integer
	case IntegerComparisonGTE:
		return v >= m.Integer
	default:
		return false
	}
}

type IntegerInMatcher struct {
	Set map[Integer]struct{}
	Not bool
}

func (m *IntegerInMatcher) Match(id ID) bool {
	i, ok := id.(Integer)
	if !ok {
		return false
	}
	_, match := m.Set[i]
	return match == !m.Not
}

type StringComparison byte

const (
	StringComparisonEqual StringComparison = iota
	StringComparisonPrefix
	StringComparisonSuffix
)

type StringComparisonMatcher struct {
	Comparison StringComparison
	String     String
}

func (m *StringComparisonMatcher) Match(id ID) bool {
	v, ok := id.(String)
	if !ok {
		return false
	}
	switch m.Comparison {
	case StringComparisonEqual:
		return m.String == v
	case StringComparisonPrefix:
		return strings.HasPrefix(v, string(m.String))
	case StringComparisonSuffix:
		return strings.HasSuffix(v, string(m.String))
	default:
		return false
	}
}

type StringInMatcher struct {
	Set map[String]struct{}
	Not bool
}

func (m *StringInMatcher) Match(id ID) bool {
	s, ok := id.(String)
	if !ok {
		return false
	}
	_, match := m.Set[s]
	return match == !m.Not
}

type StringRegexpMatcher regexp.Regexp

func (m *StringRegexpMatcher) Match(id ID) bool {
	s, ok := id.(String)
	if !ok {
		return false
	}
	return (*regexp.Regexp)(m).MatchString(string(s))
}

type DateComparison byte

const (
	DateComparisonBefore DateComparison = iota
	DateComparisonAfter
)

type DateComparisonMatcher struct {
	Comparison DateComparison
	Date       Date
}

func (m *DateComparisonMatcher) Match(id ID) bool {
	v, ok := id.(Date)
	if !ok {
		return false
	}
	switch m.Comparison {
	case DateComparisonBefore:
		return v <= m.Date
	case DateComparisonAfter:
		return v >= m.Date
	default:
		return false
	}
}

type SymbolInMatcher struct {
	Set map[Symbol]struct{}
	Not bool
}

func (m *SymbolInMatcher) Match(id ID) bool {
	sym, ok := id.(Symbol)
	if !ok {
		return false
	}
	_, match := m.Set[sym]
	return match == !m.Not
}

type InvalidMatcher struct{}

func (InvalidMatcher) Match(ID) bool { return false }

type Predicate struct {
	Name Symbol
	IDs  []ID
}

func (p Predicate) Equal(p2 Predicate) bool {
	if p.Name != p2.Name || len(p.IDs) != len(p2.IDs) {
		return false
	}
	for i, id := range p.IDs {
		if id != p2.IDs[i] {
			return false
		}
	}

	return true
}

type Fact struct {
	Predicate
}

type Constraint struct {
	ID uint32
	Matcher
}

type Rule struct {
	Head        Predicate
	Body        []Predicate
	Constraints []Constraint
}

func (r Rule) Apply(facts []Fact) ([]Fact, error) {
	vars := make([]Variable, 0, len(r.Body))
	for _, p := range r.Body {
		for _, id := range p.IDs {
			v, ok := id.(Variable)
			if !ok {
				continue
			}
			vars = append(vars, v)
		}
	}

	return nil, nil
}

type Caveat struct {
	Queries []Rule
}

type World struct {
	facts []Fact
	rules []Rule
}

func (w *World) AddFact(f Fact) {
	for _, v := range w.facts {
		if v.Equal(f.Predicate) {
			return
		}
	}
	w.facts = append(w.facts, f)
}

func (w *World) AddRule(r Rule) {
	w.rules = append(w.rules, r)
}

func (w *World) Run() error {
	return nil
}

func (w *World) Query(pred Predicate) []Fact {
	return nil
}

func (w *World) QueryRule(rule Rule) []Fact {
	return nil
}
