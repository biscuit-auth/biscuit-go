package datalog

import (
	"errors"
	"fmt"
)

// ErrUndefinedExtern is returned when an expression calls an extern function
// that is not registered.
var ErrUndefinedExtern = errors.New("datalog: undefined extern function")

// ExternFunc is a function called by the extern::name operators of datalog
// v3.3. For the unary form `left.extern::name()` right is nil; for the
// binary form `left.extern::name(right)` it is set. Strings are symbols of
// the table, which the function may extend for its result.
type ExternFunc func(symbols *SymbolTable, left Term, right Term) (Term, error)

// ExternFuncs maps function names to their implementation.
type ExternFuncs map[string]ExternFunc

func (e ExternFuncs) call(symbols *SymbolTable, name String, left Term, right Term) (Term, error) {
	fname := symbols.Str(name)
	f, ok := e[fname]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUndefinedExtern, fname)
	}
	res, err := f(symbols, left, right)
	if err != nil {
		return nil, fmt.Errorf("datalog: extern function %s: %w", fname, err)
	}
	if res == nil {
		return nil, fmt.Errorf("datalog: extern function %s returned no value", fname)
	}
	return res, nil
}
