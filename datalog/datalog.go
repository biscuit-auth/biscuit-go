// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
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

// Term is a value in a predicate. Implementations are value types and
// Equal compares by value, using a type assertion on the concrete type.
// Do not store a pointer to a term (such as *Bytes) in a Term: the
// pointer would still satisfy the interface, but Equal would not match it.
type Term interface {
	Type() TermType
	Equal(Term) bool
	String() string
}

// Keep the value types implementing Term; a pointer receiver on any of them would break Equal.
var (
	_ Term = Variable(0)
	_ Term = Integer(0)
	_ Term = String(0)
	_ Term = Date(0)
	_ Term = Bytes(nil)
	_ Term = Bool(false)
	_ Term = Set(nil)
)

type Set []Term

func (Set) Type() TermType { return TermTypeSet }

// Bytes is a slice and cannot be a map key, so look up elements with Equal.
func (s Set) contains(t Term) bool {
	for _, e := range s {
		if e.Equal(t) {
			return true
		}
	}
	return false
}

func (s Set) Equal(t Term) bool {
	c, ok := t.(Set)
	if !ok || len(c) != len(s) {
		return false
	}

	// Both directions: a duplicate on one side could otherwise hide a missing element.
	for _, e := range s {
		if !c.contains(e) {
			return false
		}
	}
	for _, e := range c {
		if !s.contains(e) {
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
	if len(eltStr) == 0 {
		return "{,}"
	}
	sort.Strings(eltStr)
	return fmt.Sprintf("{%s}", strings.Join(eltStr, ", "))
}
func (s Set) Intersect(t Set) Set {
	result := Set{}

	for _, e := range s {
		if t.contains(e) {
			result = append(result, e)
		}
	}
	return result
}
func (s Set) Union(t Set) Set {
	result := Set{}
	result = append(result, s...)

	for _, e := range t {
		if !s.contains(e) {
			result = append(result, e)
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
	return time.Unix(int64(d), 0).UTC().Format(time.RFC3339)
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
	// Scopes is the `trusting` clause; empty means the scopes of the block.
	Scopes []Scope
}

type InvalidRuleError struct {
	Rule            Rule
	MissingVariable Variable
}

func (e InvalidRuleError) Error() string {
	return fmt.Sprintf("datalog: variable %d in head is missing from body and/or constraints", e.MissingVariable)
}

// variables lists the variables of the body, unbound.
func (r Rule) variables() MatchedVariables {
	variables := make(MatchedVariables)
	for _, predicate := range r.Body {
		for _, term := range predicate.Terms {
			if v, ok := term.(Variable); ok {
				variables[v] = nil
			}
		}
	}
	return variables
}

// apply derives the facts of the rule from the visible facts and calls emit
// for each, with its origin: the origins of the matched facts plus blockID,
// the block the rule belongs to.
func (r Rule) apply(blockID BlockID, facts []factWithOrigin, syms *SymbolTable, emit func(Origin, Fact)) error {
	matches, err := combine(r.variables(), r.Body, r.Expressions, facts, syms)
	if err != nil {
		return err
	}

	for _, res := range matches {
		predicate := r.Head.Clone()
		for i, term := range predicate.Terms {
			k, ok := term.(Variable)
			if !ok {
				continue
			}
			v, ok := res.vars[k]
			if !ok {
				return InvalidRuleError{r, k}
			}

			predicate.Terms[i] = *v
		}
		emit(res.origin.With(blockID), Fact{predicate})
	}

	return nil
}

// CheckKind selects how the queries of a Check are evaluated.
type CheckKind byte

const (
	// CheckKindOne passes when one query has at least one match.
	CheckKindOne CheckKind = iota
	// CheckKindAll passes when one query has at least one match and every
	// match of that query satisfies its expressions.
	CheckKindAll
)

type Check struct {
	Queries []Rule
	Kind    CheckKind
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
			if f1.Equal(f2.Predicate) {
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

type runLimits struct {
	maxFacts      int
	maxIterations int
	maxDuration   time.Duration
}

var defaultRunLimits = runLimits{
	maxFacts:      1000,
	maxIterations: 100,
	maxDuration:   2 * time.Millisecond,
}

var (
	ErrWorldRunLimitMaxFacts      = errors.New("datalog: world runtime limit: too many facts")
	ErrWorldRunLimitMaxIterations = errors.New("datalog: world runtime limit: too many iterations")
	ErrWorldRunLimitTimeout       = errors.New("datalog: world runtime limit: timeout")
)

type WorldOption func(w *World)

func WithMaxFacts(maxFacts int) WorldOption {
	return func(w *World) {
		w.runLimits.maxFacts = maxFacts
	}
}

func WithMaxIterations(maxIterations int) WorldOption {
	return func(w *World) {
		w.runLimits.maxIterations = maxIterations
	}
}

func WithMaxDuration(maxDuration time.Duration) WorldOption {
	return func(w *World) {
		w.runLimits.maxDuration = maxDuration
	}
}

type factWithOrigin struct {
	origin Origin
	fact   Fact
}

// originFacts is the set of facts sharing one origin.
type originFacts struct {
	origin Origin
	facts  FactSet
}

type scopedRule struct {
	blockID BlockID
	trusted TrustedOrigins
	rule    Rule
}

// World holds the facts and rules of an authorization, each fact with the
// origin it derives from and each rule with the origins it trusts.
type World struct {
	// facts is kept sorted by origin so that iteration is deterministic.
	facts []originFacts
	rules []scopedRule

	runLimits runLimits
}

func NewWorld(opts ...WorldOption) *World {
	w := &World{
		runLimits: defaultRunLimits,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

// AddFact adds a fact stated by the blocks of origin. Returns false when the
// world already had it under that origin.
func (w *World) AddFact(origin Origin, f Fact) bool {
	i, found := slices.BinarySearchFunc(w.facts, origin, func(of originFacts, o Origin) int {
		return of.origin.Compare(o)
	})
	if !found {
		w.facts = slices.Insert(w.facts, i, originFacts{origin: origin.With()})
	}
	return w.facts[i].facts.Insert(f)
}

// Facts returns the facts of the world grouped by origin, in origin order.
func (w *World) Facts() []OriginFacts {
	res := make([]OriginFacts, 0, len(w.facts))
	for _, of := range w.facts {
		if len(of.facts) == 0 {
			continue
		}
		facts := make(FactSet, len(of.facts))
		copy(facts, of.facts)
		res = append(res, OriginFacts{Origin: of.origin.With(), Facts: facts})
	}
	return res
}

// OriginFacts is a group of facts sharing an origin.
type OriginFacts struct {
	Origin Origin
	Facts  FactSet
}

func (w *World) factCount() int {
	n := 0
	for _, of := range w.facts {
		n += len(of.facts)
	}
	return n
}

// visibleFacts flattens the facts whose origin is trusted.
func (w *World) visibleFacts(trusted TrustedOrigins) []factWithOrigin {
	var res []factWithOrigin
	for _, of := range w.facts {
		if !trusted.Contains(of.origin) {
			continue
		}
		for _, f := range of.facts {
			res = append(res, factWithOrigin{origin: of.origin, fact: f})
		}
	}
	return res
}

// AddRule adds a rule from block blockID, reading the facts of the trusted
// origins.
func (w *World) AddRule(blockID BlockID, trusted TrustedOrigins, r Rule) {
	w.rules = append(w.rules, scopedRule{blockID: blockID, trusted: trusted.With(), rule: r})
}

func (w *World) ResetRules() {
	w.rules = nil
}

// BlockRule is a rule with the block it belongs to.
type BlockRule struct {
	BlockID BlockID
	Rule    Rule
}

// Rules returns the rules of the world with their block, in insertion order.
func (w *World) Rules() []BlockRule {
	res := make([]BlockRule, len(w.rules))
	for i, sr := range w.rules {
		res[i] = BlockRule{BlockID: sr.blockID, Rule: sr.rule}
	}
	return res
}

// Run applies the rules until no new fact appears or a limit is reached.
func (w *World) Run(syms *SymbolTable) error {
	deadline := time.Now().Add(w.runLimits.maxDuration)
	for i := 0; i < w.runLimits.maxIterations; i++ {
		// Checked here as well so the limit applies to a world without rules.
		if time.Now().After(deadline) {
			return ErrWorldRunLimitTimeout
		}
		var newFacts []factWithOrigin
		for _, sr := range w.rules {
			if time.Now().After(deadline) {
				return ErrWorldRunLimitTimeout
			}
			visible := w.visibleFacts(sr.trusted)
			err := sr.rule.apply(sr.blockID, visible, syms, func(origin Origin, f Fact) {
				newFacts = append(newFacts, factWithOrigin{origin, f})
			})
			if err != nil {
				return err
			}
		}

		prevCount := w.factCount()
		for _, nf := range newFacts {
			w.AddFact(nf.origin, nf.fact)
		}

		newCount := w.factCount()
		if newCount >= w.runLimits.maxFacts {
			return ErrWorldRunLimitMaxFacts
		}

		// last iteration did not generate any new facts, so we can stop here
		if newCount == prevCount {
			return nil
		}
	}
	return ErrWorldRunLimitMaxIterations
}

// Query returns the facts of the trusted origins matching the predicate,
// where a variable matches any term.
func (w *World) Query(trusted TrustedOrigins, pred Predicate) *FactSet {
	res := &FactSet{}
	for _, fo := range w.visibleFacts(trusted) {
		f := fo.fact
		if f.Name != pred.Name || len(f.Terms) != len(pred.Terms) {
			continue
		}

		matches := true
		for i := 0; i < len(pred.Terms); i++ {
			if pID := pred.Terms[i]; pID.Type() != TermTypeVariable && !f.Terms[i].Equal(pID) {
				matches = false
				break
			}
		}

		if matches {
			res.Insert(f)
		}
	}
	return res
}

// QueryRule returns the facts the rule, from block blockID, derives from the
// facts of the trusted origins. An error from an expression (overflow,
// division by zero, type mismatch) is returned rather than treated as a
// non-match.
func (w *World) QueryRule(rule Rule, blockID BlockID, trusted TrustedOrigins, syms *SymbolTable) (*FactSet, error) {
	newFacts := &FactSet{}
	err := rule.apply(blockID, w.visibleFacts(trusted), syms, func(_ Origin, f Fact) {
		newFacts.Insert(f)
	})
	if err != nil {
		return nil, err
	}
	return newFacts, nil
}

// QueryMatchAll reports whether the body of the rule matches at least once
// in the facts of the trusted origins and its expressions hold for every
// match (the semantics of `check all`).
func (w *World) QueryMatchAll(rule Rule, trusted TrustedOrigins, syms *SymbolTable) (bool, error) {
	// The expressions are evaluated here rather than passed to combine, which
	// would filter the matches instead of reporting those that fail.
	matches, err := combine(rule.variables(), rule.Body, nil, w.visibleFacts(trusted), syms)
	if err != nil {
		return false, err
	}
	for _, res := range matches {
		for _, e := range rule.Expressions {
			v, err := e.Evaluate(res.vars, syms)
			if err != nil {
				return false, err
			}
			if !v.Equal(Bool(true)) {
				return false, nil
			}
		}
	}
	return len(matches) > 0, nil
}

func (w *World) Clone() *World {
	facts := make([]originFacts, len(w.facts))
	for i, of := range w.facts {
		facts[i] = originFacts{origin: of.origin.With(), facts: slices.Clone(of.facts)}
	}
	return &World{
		facts:     facts,
		rules:     slices.Clone(w.rules),
		runLimits: w.runLimits,
	}
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
	maps.Copy(res, m)
	return res
}

// match is one binding of the variables of a rule body, with the origin of
// the facts it was built from.
type match struct {
	origin Origin
	vars   MatchedVariables
}

// combine enumerates the bindings of variables for which every predicate
// matches a fact and every expression holds. The first expression error
// stops the enumeration and is returned.
func combine(
	variables MatchedVariables,
	predicates []Predicate,
	expressions []Expression,
	facts []factWithOrigin,
	syms *SymbolTable,
) ([]match, error) {
	var res []match

	current := 0
	indexes := make([]int, len(predicates))

	// cannot apply a rule on an empty list of facts
	if len(predicates) > 0 && len(facts) == 0 {
		return nil, nil
	}

	// main loop
	for {
		if len(predicates) > 0 && len(facts) > 0 {
			// look for the next matching set of facts
			// current indicates which predicate we are looking at, and indexes contains
			// a list of indexes in the facts list, for each predicate
			// when we are done looking at a set of facts, the last index is incremented
			// and if that one reached the max number of facts, the previous one, etc
			for {
				if facts[indexes[current]].fact.Match(predicates[current]) {
					if current == len(predicates)-1 {
						// extract and check variables, check expressions, send variables
						break
					} else {
						current += 1
					}
				} else {
					// did not match, we either increase the current index or the previous one
					// then we check again for a match
					if !advanceIndexes(&current, &indexes, len(facts)) {
						return res, nil
					}
				}
			}
		}

		// extract and check variables, check expressions, send variables
		var vars = variables.Clone()
		var origin Origin
		var matching = true

	match:
		for i, pred := range predicates {
			fo := facts[indexes[i]]
			origin = origin.Union(fo.origin)

			for j := 0; j < len(pred.Terms); j++ {
				term := pred.Terms[j]
				k, ok := term.(Variable)
				if !ok {
					continue
				}
				v := fo.fact.Terms[j]
				if !vars.Insert(k, v) {
					matching = false
					break match
				}

			}
		}

		if matching {
			if complete_vars := vars.Complete(); complete_vars != nil {
				valid := true
				for _, e := range expressions {
					r, err := e.Evaluate(complete_vars, syms)
					if err != nil {
						return nil, err
					}
					if !r.Equal(Bool(true)) {
						valid = false
						break
					}
				}

				if valid {
					res = append(res, match{origin, complete_vars})
				}
			} else {
				// if all predicates match but variables are not complete, it means
				// variables appearing in the head do not appear in the body,
				// so we should stop here because there's no way to get a correct match
				return res, nil
			}
		}

		// this was a rule or check with expressions but no predicates, no need to
		// update the indexes, an single execution is enough
		if len(predicates) == 0 {
			return res, nil
		}

		// next index
		if !advanceIndexes(&current, &indexes, len(facts)) {
			return res, nil
		}
	}
}

func advanceIndexes(current *int, indexes *[]int, factCount int) bool {
	for i := *current; i >= 0; i-- {
		if (*indexes)[i] < factCount-1 {
			(*indexes)[i] += 1
			break
		} else {
			if i > 0 {
				(*indexes)[i] = 0
				*current -= 1
			} else {
				// we reached the first predicate, we cannot generate more
				// combinations, so we stop the task
				return false
			}
		}
	}
	return true
}
