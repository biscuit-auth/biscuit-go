package datalog

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Checker interface {
	Check(ID) bool
	String() string
}

type IDType byte

const (
	IDTypeSymbol IDType = iota
	IDTypeVariable
	IDTypeInteger
	IDTypeString
	IDTypeDate
	IDTypeBytes
	IDTypeSet
)

type ID interface {
	Type() IDType
	Equal(ID) bool
	String() string
}

type Set []ID

func (Set) Type() IDType { return IDTypeSet }
func (s Set) Equal(t ID) bool {
	c, ok := t.(Set)
	if !ok || len(c) != len(s) {
		return false
	}

	cmap := make(map[ID]struct{}, len(c))
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

type Symbol uint64

func (Symbol) Type() IDType      { return IDTypeSymbol }
func (s Symbol) Equal(t ID) bool { c, ok := t.(Symbol); return ok && s == c }
func (s Symbol) String() string {
	return fmt.Sprintf("#%d", s)
}

type Variable uint32

func (Variable) Type() IDType      { return IDTypeVariable }
func (v Variable) Equal(t ID) bool { c, ok := t.(Variable); return ok && v == c }
func (v Variable) String() string {
	return fmt.Sprintf("$%d", v)
}

type Integer int64

func (Integer) Type() IDType      { return IDTypeInteger }
func (i Integer) Equal(t ID) bool { c, ok := t.(Integer); return ok && i == c }
func (i Integer) String() string {
	return fmt.Sprintf("%d", i)
}

type String string

func (String) Type() IDType      { return IDTypeString }
func (s String) Equal(t ID) bool { c, ok := t.(String); return ok && s == c }
func (s String) String() string {
	return fmt.Sprintf("%q", string(s))
}

type Date uint64

func (Date) Type() IDType      { return IDTypeDate }
func (d Date) Equal(t ID) bool { c, ok := t.(Date); return ok && d == c }
func (d Date) String() string {
	return time.Unix(int64(d), 0).Format(time.RFC3339)
}

type Bytes []byte

func (Bytes) Type() IDType      { return IDTypeBytes }
func (b Bytes) Equal(t ID) bool { c, ok := t.(Bytes); return ok && bytes.Equal(b, c) }
func (b Bytes) String() string {
	return fmt.Sprintf("\"hex:%s\"", hex.EncodeToString(b))
}

type IntegerComparison byte

const (
	IntegerComparisonEqual IntegerComparison = iota
	IntegerComparisonLT
	IntegerComparisonGT
	IntegerComparisonLTE
	IntegerComparisonGTE
)

type IntegerComparisonChecker struct {
	Comparison IntegerComparison
	Integer    Integer
}

func (m IntegerComparisonChecker) Check(id ID) bool {
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
func (m IntegerComparisonChecker) String() string {
	op := "??"
	switch m.Comparison {
	case IntegerComparisonEqual:
		op = "=="
	case IntegerComparisonLT:
		op = "<"
	case IntegerComparisonGT:
		op = ">"
	case IntegerComparisonLTE:
		op = "<="
	case IntegerComparisonGTE:
		op = ">="
	}
	return fmt.Sprintf("%s %s", op, m.Integer)
}

type IntegerInChecker struct {
	Set map[Integer]struct{}
	Not bool
}

func (m IntegerInChecker) Check(id ID) bool {
	if set, ok := id.(Set); ok {
		for _, subID := range set {
			if !m.Check(subID) {
				return false
			}
		}
		return true
	}

	i, ok := id.(Integer)
	if !ok {
		return false
	}
	_, ok = m.Set[i]
	return ok == !m.Not
}

func (m IntegerInChecker) String() string {
	strs := make([]string, 0, len(m.Set))
	for s := range m.Set {
		strs = append(strs, fmt.Sprintf("%d", int64(s)))
	}
	prefix := ""
	if m.Not {
		prefix = "not "
	}
	sort.Strings(strs)
	return fmt.Sprintf(prefix+"in [%s]", strings.Join(strs, ", "))
}

type StringComparison byte

const (
	StringComparisonEqual StringComparison = iota
	StringComparisonPrefix
	StringComparisonSuffix
)

type StringComparisonChecker struct {
	Comparison StringComparison
	Str        String
}

func (m StringComparisonChecker) Check(id ID) bool {
	v, ok := id.(String)
	if !ok {
		return false
	}
	switch m.Comparison {
	case StringComparisonEqual:
		return m.Str == v
	case StringComparisonPrefix:
		return strings.HasPrefix(string(v), string(m.Str))
	case StringComparisonSuffix:
		return strings.HasSuffix(string(v), string(m.Str))
	default:
		return false
	}
}

func (m StringComparisonChecker) String() string {
	var op string
	switch m.Comparison {
	case StringComparisonEqual:
		op = "=="
	case StringComparisonPrefix:
		op = "has prefix"
	case StringComparisonSuffix:
		op = "has suffix"
	}
	return fmt.Sprintf("%s %q", op, string(m.Str))
}

type StringInChecker struct {
	Set map[String]struct{}
	Not bool
}

func (m StringInChecker) Check(id ID) bool {
	if set, ok := id.(Set); ok {
		for _, subID := range set {
			if !m.Check(subID) {
				return false
			}
		}
		return true
	}

	s, ok := id.(String)
	if !ok {
		return false
	}
	_, match := m.Set[s]
	return match == !m.Not
}

func (m StringInChecker) String() string {
	strs := make([]string, 0, len(m.Set))
	for s := range m.Set {
		strs = append(strs, fmt.Sprintf("%q", string(s)))
	}
	prefix := ""
	if m.Not {
		prefix = "not "
	}
	sort.Strings(strs)
	return fmt.Sprintf(prefix+"in [%s]", strings.Join(strs, ", "))
}

type StringRegexpChecker regexp.Regexp

func (m *StringRegexpChecker) Check(id ID) bool {
	s, ok := id.(String)
	if !ok {
		return false
	}
	return (*regexp.Regexp)(m).MatchString(string(s))
}

func (m *StringRegexpChecker) String() string {
	return fmt.Sprintf("matches /%s/", (*regexp.Regexp)(m))
}

type DateComparison byte

const (
	DateComparisonBefore DateComparison = iota
	DateComparisonAfter
)

type DateComparisonChecker struct {
	Comparison DateComparison
	Date       Date
}

func (m DateComparisonChecker) Check(id ID) bool {
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

func (m DateComparisonChecker) String() string {
	var op string
	switch m.Comparison {
	case DateComparisonBefore:
		op = "<="
	case DateComparisonAfter:
		op = ">="
	}
	return fmt.Sprintf("%s %s", op, m.Date)
}

type BytesComparison byte

const (
	BytesComparisonEqual BytesComparison = iota
)

type BytesComparisonChecker struct {
	Comparison BytesComparison
	Bytes      Bytes
}

func (m BytesComparisonChecker) Check(id ID) bool {
	v, ok := id.(Bytes)
	if !ok {
		return false
	}

	switch m.Comparison {
	case BytesComparisonEqual:
		return bytes.Equal(m.Bytes, v)
	default:
		return false
	}
}

func (m BytesComparisonChecker) String() string {
	op := "??"
	switch m.Comparison {
	case BytesComparisonEqual:
		op = "=="
	}

	return fmt.Sprintf("%s %s", op, m.Bytes.String())
}

type BytesInChecker struct {
	Set map[string]struct{}
	Not bool
}

func (m BytesInChecker) Check(id ID) bool {
	if set, ok := id.(Set); ok {
		for _, subID := range set {
			if !m.Check(subID) {
				return false
			}
		}
		return true
	}

	b, ok := id.(Bytes)
	if !ok {
		return false
	}

	_, match := m.Set[string(b)]
	return match == !m.Not
}

func (m BytesInChecker) String() string {
	strs := make([]string, 0, len(m.Set))
	for s := range m.Set {
		strs = append(strs, fmt.Sprintf("%q", s))
	}
	prefix := ""
	if m.Not {
		prefix = "not "
	}
	sort.Strings(strs)
	return fmt.Sprintf(prefix+"in [%s]", strings.Join(strs, ", "))
}

type SymbolInChecker struct {
	Set map[Symbol]struct{}
	Not bool
}

func (m SymbolInChecker) Check(id ID) bool {
	if set, ok := id.(Set); ok {
		for _, subID := range set {
			if !m.Check(subID) {
				return false
			}
		}
		return true
	}

	sym, ok := id.(Symbol)
	if !ok {
		return false
	}
	_, match := m.Set[sym]
	return match == !m.Not
}

func (m SymbolInChecker) String() string {
	strs := make([]string, 0, len(m.Set))
	for s := range m.Set {
		strs = append(strs, fmt.Sprintf("%q", uint32(s)))
	}
	prefix := ""
	if m.Not {
		prefix = "not "
	}
	sort.Strings(strs)
	return fmt.Sprintf(prefix+"in [%s]", strings.Join(strs, ", "))
}

type InvalidChecker struct{}

func (InvalidChecker) Match(ID) bool { return false }

type Predicate struct {
	Name Symbol
	IDs  []ID
}

func (p Predicate) Equal(p2 Predicate) bool {
	if p.Name != p2.Name || len(p.IDs) != len(p2.IDs) {
		return false
	}
	for i, id := range p.IDs {
		if !id.Equal(p2.IDs[i]) {
			return false
		}
	}

	return true
}

func (p Predicate) Match(p2 Predicate) bool {
	if p.Name != p2.Name || len(p.IDs) != len(p2.IDs) {
		return false
	}
	for i, id := range p.IDs {
		_, v1 := id.(Variable)
		_, v2 := p2.IDs[i].(Variable)
		if v1 || v2 {
			continue
		}
		if !id.Equal(p2.IDs[i]) {
			return false
		}
	}
	return true
}

func (p Predicate) Clone() Predicate {
	res := Predicate{Name: p.Name, IDs: make([]ID, len(p.IDs))}
	copy(res.IDs, p.IDs)
	return res
}

type Fact struct {
	Predicate
}

type Constraint struct {
	Name Variable
	Checker
}

func (c Constraint) Check(name Variable, id ID) bool {
	if c.Name != name {
		return true
	}
	if _, ok := id.(Variable); ok {
		panic("should not check constraint on a variable")
	}
	return c.Checker.Check(id)
}

func (c Constraint) String() string {
	return fmt.Sprintf("%v %v", c.Name, c.Checker)
}

type Rule struct {
	Head        Predicate
	Body        []Predicate
	Constraints []Constraint
}

type InvalidRuleError struct {
	Rule            Rule
	MissingVariable Variable
}

func (e InvalidRuleError) Error() string {
	return fmt.Sprintf("datalog: variable %d in head is missing from body and/or constraints", e.MissingVariable)
}

func (r Rule) Apply(facts *FactSet, newFacts *FactSet) error {
	// extract all variables from the rule body
	variables := make(MatchedVariables)
	for _, p := range r.Body {
		for _, id := range p.IDs {
			v, ok := id.(Variable)
			if !ok {
				continue
			}
			variables[v] = nil
		}
	}

	for _, h := range NewCombinator(variables, r.Body, r.Constraints, facts).Combine() {
		p := r.Head.Clone()
		for i, id := range p.IDs {
			k, ok := id.(Variable)
			if !ok {
				continue
			}
			v, ok := h[k]
			if !ok {
				return InvalidRuleError{r, k}
			}
			p.IDs[i] = *v
		}
		newFacts.Insert(Fact{p})
	}

	return nil
}

type Caveat struct {
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

type World struct {
	facts *FactSet
	rules []Rule
}

func NewWorld() *World {
	return &World{facts: &FactSet{}}
}

func (w *World) AddFact(f Fact) {
	w.facts.Insert(f)
}

func (w *World) AddRule(r Rule) {
	w.rules = append(w.rules, r)
}

func (w *World) Run() error {
	for i := 0; i < 100; i++ {
		var newFacts FactSet
		for _, r := range w.rules {
			if err := r.Apply(w.facts, &newFacts); err != nil {
				return err
			}
		}
		l := len(*w.facts)
		w.facts.InsertAll([]Fact(newFacts))
		if len(*w.facts) == l {
			return nil
		}
	}
	return fmt.Errorf("datalog: world ran more than 100 iterations")
}

func (w *World) Query(pred Predicate) *FactSet {
	res := &FactSet{}
	for _, f := range *w.facts {
		if f.Predicate.Name != pred.Name {
			continue
		}
		minLen := len(f.Predicate.IDs)
		if l := len(pred.IDs); l < minLen {
			minLen = l
		}
		for i := 0; i < minLen; i++ {
			fID := f.Predicate.IDs[i]
			pID := pred.IDs[i]
			if fID.Type() != IDTypeVariable && fID.Type() == pID.Type() {
				if fID != pID {
					continue
				}
			} else if fID.Type() != IDTypeSymbol && pID.Type() != IDTypeVariable {
				continue
			}
			res.Insert(f)
		}
	}
	return res
}

func (w *World) QueryRule(rule Rule) *FactSet {
	newFacts := &FactSet{}
	rule.Apply(w.facts, newFacts)
	return newFacts
}

func (w *World) Clone() *World {
	newFacts := new(FactSet)
	*newFacts = *w.facts
	return &World{
		facts: newFacts,
		rules: append([]Rule{}, w.rules...),
	}
}

type MatchedVariables map[Variable]*ID

func (m MatchedVariables) Insert(k Variable, v ID) bool {
	existing := m[k]
	if existing == nil {
		m[k] = &v
		return true
	}
	return v.Equal(*existing)
}

func (m MatchedVariables) Complete() map[Variable]*ID {
	for _, v := range m {
		if v == nil {
			return nil
		}
	}
	return (map[Variable]*ID)(m)
}

func (m MatchedVariables) Clone() MatchedVariables {
	res := make(MatchedVariables, len(m))
	for k, v := range m {
		res[k] = v
	}
	return res
}

type Combinator struct {
	variables    MatchedVariables
	predicates   []Predicate
	constraints  []Constraint
	allFacts     *FactSet
	currentFacts *FactSet
}

func NewCombinator(variables MatchedVariables, predicates []Predicate, constraints []Constraint, allFacts *FactSet) *Combinator {
	c := &Combinator{
		variables:   variables,
		predicates:  predicates,
		constraints: constraints,
		allFacts:    allFacts,
	}
	currentFacts := make(FactSet, 0, len(*allFacts))
	for _, f := range *allFacts {
		if len(predicates) > 0 && f.Match(predicates[0]) {
			currentFacts = append(currentFacts, f)
		}
	}
	c.currentFacts = &currentFacts
	return c
}

func (c *Combinator) Combine() []map[Variable]*ID {
	var variables []map[Variable]*ID
	// Stop when no more predicates are available
	if len(c.predicates) == 0 {
		if vars := c.variables.Complete(); vars != nil {
			variables = append(variables, vars)
		}
		return variables
	}

	for i, pred := range c.predicates {
		for ii, currentFact := range *c.currentFacts {
			vars := c.variables.Clone()
			matchIDs := true
			// minLen is the smallest number of IDs
			// between the predicate and the current fact
			minLen := len(pred.IDs)
			if l := len(currentFact.Predicate.IDs); l < minLen {
				minLen = l
			}

			for j := 0; j < minLen; j++ {
				id := pred.IDs[j]
				k, ok := id.(Variable)
				if !ok {
					continue
				}
				v := currentFact.Predicate.IDs[j]
				for _, con := range c.constraints {
					if !con.Check(k, v) {
						matchIDs = false
						break
					}
				}
				if !vars.Insert(k, v) {
					matchIDs = false
				}
				if !matchIDs {
					break
				}
			}

			if !matchIDs {
				continue
			}

			if len(c.predicates) > i+1 {
				next := NewCombinator(vars, c.predicates[i+1:], c.constraints, c.allFacts).Combine()
				if len(next) == 0 {
					// returns only if there is no more current facts, otherwise process next one
					if ii == len(*c.currentFacts)-1 {
						return variables
					}
					continue
				}
				variables = append(variables, next...)
			} else {
				if v := vars.Complete(); v != nil {
					variables = append(variables, v)
				}
			}
		}
	}
	return variables
}

type SymbolTable []string

func (t *SymbolTable) Insert(s string) Symbol {
	for i, v := range *t {
		if string(v) == s {
			return Symbol(i)
		}
	}
	*t = append(*t, s)
	return Symbol(len(*t) - 1)
}

func (t *SymbolTable) Sym(s string) ID {
	for i, v := range *t {
		if string(v) == s {
			return Symbol(i)
		}
	}
	return nil
}

func (t *SymbolTable) Str(sym Symbol) string {
	if int(sym) > len(*t)-1 {
		return fmt.Sprintf("<invalid symbol %d>", sym)
	}
	return (*t)[int(sym)]
}

func (t *SymbolTable) Clone() *SymbolTable {
	newTable := *t
	return &newTable
}

// SplitOff returns a newly allocated slice containing the elements in the range
// [at, len). After the call, the receiver will be left containing
// the elements [0, at) with its previous capacity unchanged.
func (t *SymbolTable) SplitOff(at int) *SymbolTable {
	if at > len(*t) {
		panic("split index out of bound")
	}

	new := make(SymbolTable, len(*t)-at)
	copy(new, (*t)[at:])

	*t = (*t)[:at]

	return &new
}

func (t *SymbolTable) Len() int {
	return len(*t)
}

// IsDisjoint returns true if receiver has no elements in common with other.
// This is equivalent to checking for an empty intersection.
func (t *SymbolTable) IsDisjoint(other *SymbolTable) bool {
	m := make(map[string]struct{}, len(*t))
	for _, s := range *t {
		m[s] = struct{}{}
	}

	for _, os := range *other {
		if _, ok := m[os]; ok {
			return false
		}
	}

	return true
}

func (t *SymbolTable) Extend(other *SymbolTable) {
	*t = append(*t, *other...)
}

type SymbolDebugger struct {
	*SymbolTable
}

func (d SymbolDebugger) Predicate(p Predicate) string {
	strs := make([]string, len(p.IDs))
	for i, id := range p.IDs {
		var s string
		if sym, ok := id.(Symbol); ok {
			s = "#" + d.Str(sym)
		} else {
			s = fmt.Sprintf("%v", id)
		}
		strs[i] = s
	}
	return fmt.Sprintf("%s(%s)", d.Str(p.Name), strings.Join(strs, ", "))
}

func (d SymbolDebugger) Rule(r Rule) string {
	head := d.Predicate(r.Head)
	preds := make([]string, len(r.Body))
	for i, p := range r.Body {
		preds[i] = d.Predicate(p)
	}
	constraints := make([]string, len(r.Constraints))
	for i, c := range r.Constraints {
		constraints[i] = c.String()
	}

	var constraintStart string
	if len(constraints) > 0 {
		constraintStart = " @ "
	}

	return fmt.Sprintf("*%s <- %s%s%s", head, strings.Join(preds, ", "), constraintStart, strings.Join(constraints, ", "))
}

func (d SymbolDebugger) Caveat(c Caveat) string {
	queries := make([]string, len(c.Queries))
	for i, q := range c.Queries {
		queries[i] = d.Rule(q)
	}
	return strings.Join(queries, " || ")
}

func (d SymbolDebugger) World(w *World) string {
	facts := make([]string, len(*w.facts))
	for i, f := range *w.facts {
		facts[i] = d.Predicate(f.Predicate)
	}
	rules := make([]string, len(w.rules))
	for i, r := range w.rules {
		rules[i] = d.Rule(r)
	}
	return fmt.Sprintf("World {{\n\tfacts: %v\n\trules: %v\n}}", facts, rules)
}

func (d SymbolDebugger) FactSet(s *FactSet) string {
	strs := make([]string, len(*s))
	for i, f := range *s {
		strs[i] = d.Predicate(f.Predicate)
	}
	return fmt.Sprintf("%v", strs)
}
