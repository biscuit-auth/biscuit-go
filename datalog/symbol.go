// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

var DEFAULT_SYMBOLS = [...]string{
	"read",
	"write",
	"resource",
	"operation",
	"right",
	"time",
	"role",
	"owner",
	"tenant",
	"namespace",
	"user",
	"team",
	"service",
	"admin",
	"email",
	"group",
	"member",
	"ip_address",
	"client",
	"client_ip",
	"domain",
	"path",
	"version",
	"cluster",
	"node",
	"hostname",
	"nonce",
	"query",
}

var OFFSET = 1024

type SymbolTable []string

func (t *SymbolTable) Insert(s string) String {
	for i, v := range DEFAULT_SYMBOLS {
		if string(v) == s {
			return String(i)
		}
	}

	for i, v := range *t {
		if string(v) == s {
			return String(OFFSET + i)
		}
	}
	*t = append(*t, s)

	return String(OFFSET + len(*t) - 1)
}

func (t *SymbolTable) Sym(s string) Term {
	for i, v := range DEFAULT_SYMBOLS {
		if string(v) == s {
			return String(i)
		}
	}

	for i, v := range *t {
		if string(v) == s {
			return String(OFFSET + i)
		}
	}
	return nil
}

func (t *SymbolTable) Index(s string) uint64 {
	for i, v := range DEFAULT_SYMBOLS {
		if string(v) == s {
			return uint64(i)
		}
	}

	for i, v := range *t {
		if string(v) == s {
			return uint64(OFFSET + i)
		}
	}
	panic("index not found")
}

func (t *SymbolTable) Str(sym String) string {
	if int(sym) < 1024 {
		if int(sym) > len(DEFAULT_SYMBOLS)-1 {
			return fmt.Sprintf("<invalid symbol %d>", sym)
		} else {
			return DEFAULT_SYMBOLS[int(sym)]
		}
	}
	if int(sym)-1024 > len(*t)-1 {
		return fmt.Sprintf("<invalid symbol %d>", sym)
	}
	return (*t)[int(sym)-1024]
}

func (t *SymbolTable) Var(v Variable) string {
	if int(v) < 1024 {
		if int(v) > len(DEFAULT_SYMBOLS)-1 {
			return fmt.Sprintf("<invalid variable %d>", v)
		} else {
			return DEFAULT_SYMBOLS[int(v)]
		}
	}
	if int(v)-1024 > len(*t)-1 {
		return fmt.Sprintf("<invalid variable %d>", v)
	}
	return (*t)[int(v)-1024]
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

	table := make(SymbolTable, len(*t)-at)
	copy(table, (*t)[at:])

	*t = (*t)[:at]

	return &table
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

// Extend insert symbols from the given SymbolTable in the receiving one
// excluding any Symbols already existing
func (t *SymbolTable) Extend(other *SymbolTable) {
	for _, s := range *other {
		t.Insert(s)
	}
}

type SymbolDebugger struct {
	*SymbolTable
}

// Term prints a term, resolving strings and variables through the symbol
// table, including inside sets.
func (d SymbolDebugger) Term(t Term) string {
	switch t := t.(type) {
	case String:
		return "\"" + d.Str(t) + "\""
	case Variable:
		return "$" + d.Var(t)
	case Set:
		if len(t) == 0 {
			return "{,}"
		}
		elts := make([]string, len(t))
		for i, e := range t {
			elts[i] = d.Term(e)
		}
		sort.Strings(elts)
		return fmt.Sprintf("{%s}", strings.Join(elts, ", "))
	default:
		return t.String()
	}
}

func (d SymbolDebugger) Predicate(p Predicate) string {
	strs := make([]string, len(p.Terms))
	for i, id := range p.Terms {
		strs[i] = d.Term(id)
	}
	return fmt.Sprintf("%s(%s)", d.Str(p.Name), strings.Join(strs, ", "))
}

func (d SymbolDebugger) Rule(r Rule) string {
	head := d.Predicate(r.Head)
	preds := make([]string, len(r.Body))
	for i, p := range r.Body {
		preds[i] = d.Predicate(p)
	}
	expressions := make([]string, len(r.Expressions))
	for i, e := range r.Expressions {
		expressions[i] = d.Expression(e)
	}

	var expressionsStart string
	if len(preds) > 0 && len(expressions) > 0 {
		expressionsStart = ", "
	}

	return fmt.Sprintf("%s <- %s%s%s%s", head, strings.Join(preds, ", "), expressionsStart, strings.Join(expressions, ", "), ScopesString(r.Scopes))
}

func (d SymbolDebugger) CheckQuery(r Rule) string {
	preds := make([]string, len(r.Body))
	for i, p := range r.Body {
		preds[i] = d.Predicate(p)
	}
	expressions := make([]string, len(r.Expressions))
	for i, e := range r.Expressions {
		expressions[i] = d.Expression(e)
	}

	var expressionsStart string
	if len(preds) > 0 && len(expressions) > 0 {
		expressionsStart = ", "
	}

	return fmt.Sprintf("%s%s%s%s", strings.Join(preds, ", "), expressionsStart, strings.Join(expressions, ", "), ScopesString(r.Scopes))
}

func (d SymbolDebugger) Expression(e Expression) string {
	return e.Print(d.SymbolTable)
}

func (d SymbolDebugger) Check(c Check) string {
	queries := make([]string, len(c.Queries))
	for i, q := range c.Queries {
		queries[i] = d.CheckQuery(q)
	}
	kind := "check if"
	switch c.Kind {
	case CheckKindAll:
		kind = "check all"
	case CheckKindReject:
		kind = "reject if"
	}
	return fmt.Sprintf("%s %s", kind, strings.Join(queries, " or "))
}

// World prints the facts grouped by origin and the rules by block, each
// group sorted, in the layout of the reference implementation:
//
//	// origin: [0]
//	fact(1);
//	// origin: authorizer
//	rule($a) <- fact($a);
func (d SymbolDebugger) World(w *World) string {
	var b strings.Builder
	if len(w.facts) > 0 {
		b.WriteString("// Facts:\n")
	}
	for _, of := range w.facts {
		if len(of.facts) == 0 {
			continue
		}
		facts := make([]string, len(of.facts))
		for i, f := range of.facts {
			facts[i] = d.Predicate(f.Predicate)
		}
		sort.Strings(facts)
		fmt.Fprintf(&b, "// origin: %s\n", of.origin)
		for _, f := range facts {
			fmt.Fprintf(&b, "%s;\n", f)
		}
	}

	rulesByBlock := map[BlockID][]string{}
	for _, sr := range w.rules {
		rulesByBlock[sr.blockID] = append(rulesByBlock[sr.blockID], d.Rule(sr.rule))
	}
	if len(rulesByBlock) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("// Rules:\n")
	}
	blocks := make([]BlockID, 0, len(rulesByBlock))
	for id := range rulesByBlock {
		blocks = append(blocks, id)
	}
	slices.Sort(blocks)
	for _, id := range blocks {
		rules := rulesByBlock[id]
		sort.Strings(rules)
		fmt.Fprintf(&b, "// origin: %s\n", id)
		for _, r := range rules {
			fmt.Fprintf(&b, "%s;\n", r)
		}
	}
	return b.String()
}

func (d SymbolDebugger) FactSet(s *FactSet) string {
	strs := make([]string, len(*s))
	for i, f := range *s {
		strs[i] = d.Predicate(f.Predicate)
	}
	return fmt.Sprintf("%v", strs)
}
