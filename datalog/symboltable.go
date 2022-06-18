package datalog

import "fmt"

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

// Extend insert symbols from the given SymbolTable in the receiving one
// excluding any Symbols already existing
func (t *SymbolTable) Extend(other *SymbolTable) {
	for _, s := range *other {
		t.Insert(s)
	}
}
