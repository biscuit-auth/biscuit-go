package datalog

import (
	"crypto/sha256"
	"testing"
)

func hashVar(s string) Variable {
	h := sha256.Sum256([]byte(s))
	id := uint32(h[0]) +
		uint32(h[1])<<8 +
		uint32(h[2])<<16 +
		uint32(h[3])<<24
	return Variable(id)
}

func TestFamily(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	a := syms.Insert("A")
	b := syms.Insert("B")
	c := syms.Insert("C")
	d := syms.Insert("D")
	//e := syms.Insert("e")
	parent := syms.Insert("parent")
	grandparent := syms.Insert("grandparent")
	//sibling := syms.Insert("sibling")

	w.AddFact(Fact{Predicate{parent, []ID{a, b}}})
	w.AddFact(Fact{Predicate{parent, []ID{b, c}}})
	w.AddFact(Fact{Predicate{parent, []ID{c, d}}})

	r1 := Rule{
		Head: Predicate{grandparent, []ID{hashVar("grandparent"), hashVar("grandchild")}},
		Body: []Predicate{
			{parent, []ID{hashVar("grandparent"), hashVar("parent")}},
			{parent, []ID{hashVar("parent"), hashVar("grandchild")}},
		},
	}

	t.Logf("testing r1: %s", syms.PrintRule(r1))
	queryRuleResult := w.QueryRule(r1)
	t.Logf("r1 query: %s", syms.PrintFactSet(queryRuleResult))
	t.Logf("current facts: %s", syms.PrintFactSet(w.facts))
}
