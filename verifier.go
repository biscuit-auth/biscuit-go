package biscuit

import (
	"errors"
	"fmt"
	"strings"

	"github.com/flynn/biscuit-go/datalog"
)

var (
	ErrMissingSymbols   = errors.New("biscuit: missing symbols")
	ErrPolicyDenied     = errors.New("biscuit: denied by policy")
	ErrNoMatchingPolicy = errors.New("biscuit: denied by no matching policies")
)

type Verifier interface {
	AddFact(fact Fact)
	AddRule(rule Rule)
	AddCheck(check Check)
	AddPolicy(policy Policy)
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
	checks      []Check
	policies    []Policy
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
		checks:      []Check{},
	}, nil
}

func (v *verifier) AddFact(fact Fact) {
	v.world.AddFact(fact.convert(v.symbols))
}

func (v *verifier) AddRule(rule Rule) {
	v.world.AddRule(rule.convert(v.symbols))
}

func (v *verifier) AddCheck(check Check) {
	v.checks = append(v.checks, check)
}

func (v *verifier) AddPolicy(policy Policy) {
	v.policies = append(v.policies, policy)
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

	for i, check := range v.checks {
		c := check.convert(v.symbols)
		successful := false
		for _, query := range c.Queries {
			res := v.world.QueryRule(query)
			if len(*res) != 0 {
				successful = true
				break
			}
		}
		if !successful {
			errs = append(errs, fmt.Errorf("failed to verify check #%d: %s", i, debug.Check(c)))
		}
	}

	for bi, blockChecks := range v.biscuit.Checks() {
		for ci, check := range blockChecks {
			successful := false
			for _, query := range check.Queries {
				res := v.world.QueryRule(query)
				if len(*res) != 0 {
					successful = true
					break
				}
			}
			if !successful {
				errs = append(errs, fmt.Errorf("failed to verify block #%d check #%d: %s", bi, ci, debug.Check(check)))
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

	for _, policy := range v.policies {
		for _, query := range policy.Queries {
			res := v.world.QueryRule(query.convert(v.symbols))
			if len(*res) != 0 {
				switch policy.Kind {
				case PolicyKindAllow:
					return nil
				case PolicyKindDeny:
					return ErrPolicyDenied
				}
			}
		}
	}

	return ErrNoMatchingPolicy
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
	v.checks = []Check{}
	v.world = v.baseWorld.Clone()
	v.symbols = v.baseSymbols.Clone()
}
