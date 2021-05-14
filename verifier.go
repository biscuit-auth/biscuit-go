package biscuit

import (
	"errors"
	"fmt"
	"strings"

	"github.com/biscuit-auth/biscuit-go/datalog"
)

var (
	ErrMissingSymbols = errors.New("biscuit: missing symbols")
)

type Verifier interface {
	AddFact(fact Fact)
	AddRule(rule Rule)
	AddCaveat(caveat Caveat)
	Verify() error
	Query(rule Rule) (FactSet, error)
	Biscuit() *Biscuit
	Reset()
	PrintWorld() string
}

type verifier struct {
	biscuit     *Biscuit
	baseWorld   *datalog.World
	baseSymbols *datalog.SymbolTable
	world       *datalog.World
	symbols     *datalog.SymbolTable
	caveats     []Caveat
}

var _ Verifier = (*verifier)(nil)

func NewVerifier(b *Biscuit) (Verifier, error) {
	baseWorld, err := b.generateWorld(b.symbols)
	if err != nil {
		return nil, err
	}

	return &verifier{
		biscuit:     b,
		baseWorld:   baseWorld,
		baseSymbols: b.symbols.Clone(),
		world:       baseWorld.Clone(),
		symbols:     b.symbols.Clone(),
		caveats:     []Caveat{},
	}, nil
}

func (v *verifier) AddFact(fact Fact) {
	v.world.AddFact(fact.convert(v.symbols))
}

func (v *verifier) AddRule(rule Rule) {
	v.world.AddRule(rule.convert(v.symbols))
}

func (v *verifier) AddCaveat(caveat Caveat) {
	v.caveats = append(v.caveats, caveat)
}

func (v *verifier) Verify() error {
	debug := datalog.SymbolDebugger{
		SymbolTable: v.symbols,
	}

	if v.symbols.Sym("authority") == nil || v.symbols.Sym("ambient") == nil {
		return ErrMissingSymbols
	}

	if err := v.world.Run(); err != nil {
		return err
	}

	var errs []error

	for i, caveat := range v.caveats {
		c := caveat.convert(v.symbols)
		successful := false
		for _, query := range c.Queries {
			res := v.world.QueryRule(query)
			if len(*res) != 0 {
				successful = true
				break
			}
		}
		if !successful {
			errs = append(errs, fmt.Errorf("failed to verify caveat #%d: %s", i, debug.Caveat(c)))
		}
	}

	for bi, blockCaveats := range v.biscuit.Caveats() {
		for ci, caveat := range blockCaveats {
			successful := false
			for _, query := range caveat.Queries {
				res := v.world.QueryRule(query)
				if len(*res) != 0 {
					successful = true
					break
				}
			}
			if !successful {
				errs = append(errs, fmt.Errorf("failed to verify block #%d caveat #%d: %s", bi, ci, debug.Caveat(caveat)))
			}
		}
	}

	if len(errs) > 0 {
		errMsg := make([]string, len(errs))
		for i, e := range errs {
			errMsg[i] = e.Error()
		}
		return fmt.Errorf("biscuit: verification failed: %s", strings.Join(errMsg, ", "))
	}

	return nil
}

func (v *verifier) Query(rule Rule) (FactSet, error) {
	if err := v.world.Run(); err != nil {
		return nil, err
	}

	facts := v.world.QueryRule(rule.convert(v.symbols))

	result := make([]Fact, 0, len(*facts))
	for _, fact := range *facts {
		f, err := fromDatalogFact(v.symbols, fact)
		if err != nil {
			return nil, err
		}

		result = append(result, *f)
	}

	return result, nil
}

func (v *verifier) Biscuit() *Biscuit {
	return v.biscuit
}

func (v *verifier) PrintWorld() string {
	debug := datalog.SymbolDebugger{
		SymbolTable: v.symbols,
	}

	return debug.World(v.world)
}

func (v *verifier) Reset() {
	v.caveats = []Caveat{}
	v.world = v.baseWorld.Clone()
	v.symbols = v.baseSymbols.Clone()
}
