package biscuit

import (
	"testing"
	"time"

	"github.com/flynn/biscuit-go/datalog"
	"github.com/stretchr/testify/require"
)

func TestFromDatalogFact(t *testing.T) {
	now := time.Now()

	symbolTable := &datalog.SymbolTable{"sym0", "sym1"}
	dlFact := datalog.Fact{
		Predicate: datalog.Predicate{
			Name: datalog.Symbol(0),
			IDs: []datalog.ID{
				datalog.Symbol(1),
				datalog.Integer(42),
				datalog.String("foo"),
				datalog.Variable(12),
				datalog.Date(now.Unix()),
			},
		},
	}

	fact, err := fromDatalogFact(symbolTable, dlFact)
	require.NoError(t, err)

	expectedFact := &Fact{
		Predicate: Predicate{
			Name: "sym0",
			IDs: []Atom{
				Symbol("sym1"),
				Integer(42),
				String("foo"),
				Variable(12),
				Date(time.Unix(now.Unix(), 0)),
			},
		},
	}
	require.Equal(t, expectedFact, fact)
}
