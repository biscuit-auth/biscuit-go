package datalog

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

type TermType byte

const (
	TermTypeVariable TermType = iota
	TermTypeInteger
	TermTypeString
	TermTypeDate
	TermTypeBytes
	TermTypeBool
	TermTypeSet
)

type Term interface {
	Type() TermType
	Equal(Term) bool
	String() string
}

type Set []Term

func (Set) Type() TermType { return TermTypeSet }
func (s Set) Equal(t Term) bool {
	c, ok := t.(Set)
	if !ok || len(c) != len(s) {
		return false
	}

	cmap := make(map[Term]struct{}, len(c))
	for _, v := range c {
		cmap[v] = struct{}{}
	}

	for _, id := range s {
		if _, ok := cmap[id]; !ok {
			return false
		}
	}
	return true
}
func (s Set) String() string {
	eltStr := make([]string, 0, len(s))
	for _, e := range s {
		eltStr = append(eltStr, e.String())
	}
	sort.Strings(eltStr)
	return fmt.Sprintf("[%s]", strings.Join(eltStr, ", "))
}
func (s Set) Intersect(t Set) Set {
	other := make(map[Term]struct{}, len(t))
	for _, v := range t {
		other[v] = struct{}{}
	}

	result := Set{}

	for _, id := range s {
		if _, ok := other[id]; ok {
			result = append(result, id)
		}
	}
	return result
}
func (s Set) Union(t Set) Set {
	this := make(map[Term]struct{}, len(s))
	for _, v := range s {
		this[v] = struct{}{}
	}

	result := Set{}
	result = append(result, s...)

	for _, id := range t {
		if _, ok := this[id]; !ok {
			result = append(result, id)
		}
	}

	return result
}

type Variable uint32

func (Variable) Type() TermType      { return TermTypeVariable }
func (v Variable) Equal(t Term) bool { c, ok := t.(Variable); return ok && v == c }
func (v Variable) String() string {
	return fmt.Sprintf("$%d", v)
}

type Integer int64

func (Integer) Type() TermType      { return TermTypeInteger }
func (i Integer) Equal(t Term) bool { c, ok := t.(Integer); return ok && i == c }
func (i Integer) String() string {
	return fmt.Sprintf("%d", i)
}

type String uint64

func (String) Type() TermType      { return TermTypeString }
func (s String) Equal(t Term) bool { c, ok := t.(String); return ok && s == c }
func (s String) String() string {
	return fmt.Sprintf("#%d", s)
}

type Date uint64

func (Date) Type() TermType      { return TermTypeDate }
func (d Date) Equal(t Term) bool { c, ok := t.(Date); return ok && d == c }
func (d Date) String() string {
	return time.Unix(int64(d), 0).Format(time.RFC3339)
}

type Bytes []byte

func (Bytes) Type() TermType      { return TermTypeBytes }
func (b Bytes) Equal(t Term) bool { c, ok := t.(Bytes); return ok && bytes.Equal(b, c) }
func (b Bytes) String() string {
	return fmt.Sprintf("hex:%s", hex.EncodeToString(b))
}

type Bool bool

func (Bool) Type() TermType      { return TermTypeBool }
func (b Bool) Equal(t Term) bool { c, ok := t.(Bool); return ok && b == c }
func (b Bool) String() string {
	return fmt.Sprintf("%t", b)
}

type Predicate struct {
	Name  String
	Terms []Term
}

func (p Predicate) Equal(p2 Predicate) bool {
	if p.Name != p2.Name || len(p.Terms) != len(p2.Terms) {
		return false
	}
	for i, id := range p.Terms {
		if !id.Equal(p2.Terms[i]) {
			return false
		}
	}

	return true
}

func (p Predicate) Match(p2 Predicate) bool {
	if p.Name != p2.Name || len(p.Terms) != len(p2.Terms) {
		return false
	}
	for i, id := range p.Terms {
		_, v1 := id.(Variable)
		_, v2 := p2.Terms[i].(Variable)
		if v1 || v2 {
			continue
		}
		// if both of the predicates are not a Variable, compare
		if !id.Equal(p2.Terms[i]) {
			return false
		}
	}
	return true
}

func (p Predicate) Clone() Predicate {
	res := Predicate{Name: p.Name, Terms: make([]Term, len(p.Terms))}
	copy(res.Terms, p.Terms)
	return res
}

type Fact struct {
	Predicate
}

type Rule struct {
	Head        Predicate
	Body        []Predicate
	Expressions []Expression

	forbiddenIDs []Term
}

type InvalidRuleError struct {
	Rule            Rule
	MissingVariable Variable
}

func (e InvalidRuleError) Error() string {
	return fmt.Sprintf("datalog: variable %d in head is missing from body and/or constraints", e.MissingVariable)
}

type Check struct {
	Queries []Rule
}

type FactSet []Fact

func (s *FactSet) Insert(f Fact) bool {
	for _, v := range *s {
		if v.Equal(f.Predicate) {
			return false
		}
	}
	*s = append(*s, f)
	return true
}

func (s *FactSet) InsertAll(facts []Fact) {
	for _, f := range facts {
		s.Insert(f)
	}
}

func (s *FactSet) Equal(x *FactSet) bool {
	if len(*s) != len(*x) {
		return false
	}
	for _, f1 := range *x {
		found := false
		for _, f2 := range *s {
			if f1.Predicate.Equal(f2.Predicate) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type MatchedVariables map[Variable]*Term

func (m MatchedVariables) Insert(k Variable, v Term) bool {
	existing := m[k]
	if existing == nil {
		m[k] = &v
		return true
	}
	return v.Equal(*existing)
}

func (m MatchedVariables) Complete() map[Variable]*Term {
	for _, v := range m {
		if v == nil {
			return nil
		}
	}
	return (map[Variable]*Term)(m)
}

func (m MatchedVariables) Clone() MatchedVariables {
	res := make(MatchedVariables, len(m))
	for k, v := range m {
		res[k] = v
	}
	return res
}

func (r Rule) Apply(facts *FactSet, newFacts *FactSet, syms *SymbolTable) error {
	// extract all variables from the rule body
	variables := make(MatchedVariables)
	for _, p := range r.Body {
		for _, id := range p.Terms {
			v, ok := id.(Variable)
			if !ok {
				continue
			}
			variables[v] = nil
		}
	}

	solv, err := NewSolver(r.Body, r.Expressions, facts, syms)
	if err != nil {
		return err
	}
	err = solv.Solve(0, variables)
	if err != nil {
		return err
	}
	if len(solv.solutions) == 0 {
		switch len(variables) {
		case 0:
			// special case, query with Facts
			return nil
		default:
			myErr := &SolvSafeForWorldError{
				errMsg: "datalog: solver didn't find a matching solution",
			}
			return myErr
		}
	}
outer:
	for _, h := range solv.solutions {
		p := r.Head.Clone()
		for i, id := range p.Terms {
			k, ok := id.(Variable)
			if !ok {
				// TODO: Check if this really works with a Rule where head has a non-var Pred
				// see test13, test Token has the follwing in block 1
				// valid_date("file1") <- time($0), resource("file1"), $0 <= 2030-12-31T12:59:59Z;
				continue
			}
			v, ok := h[k]
			if !ok {
				return InvalidRuleError{r, k}
			}

			// prevent the rule from generating facts with forbidden IDs
			for _, f := range r.forbiddenIDs {
				if f.Equal(*v) {
					continue outer
				}
			}

			p.Terms[i] = *v
		}
		newFacts.Insert(Fact{p})
	}

	return nil
}
