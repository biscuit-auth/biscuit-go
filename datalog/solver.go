package datalog

import (
	"fmt"
)

// SolvSafeForWorldError allows to make an error that will not cause
// failed state while Authoriser reconciles the facts using rules
type SolvSafeForWorldError struct {
	errMsg string
}

func (e SolvSafeForWorldError) Error() string {
	return e.errMsg
}

func (e SolvSafeForWorldError) Is(target error) bool {
	if _, ok := target.(*SolvSafeForWorldError); ok {
		return true
	}
	return false
}

type Solver struct {
	predicates  []Predicate
	expressions []Expression
	allFacts    *FactSet
	predToFacts [][]*Fact
	solutions   []MatchedVariables
	symDeb      SymbolDebugger
	syms        *SymbolTable
}

// NewSolver prepeares a Solver instance, will return an error if there are no matching Facts for a Predicate
func NewSolver(predicates []Predicate, expressions []Expression, allFacts *FactSet, syms *SymbolTable) (*Solver, error) {
	c := &Solver{
		predicates:  predicates,
		expressions: expressions,
		allFacts:    allFacts,
		symDeb:      SymbolDebugger{syms},
		syms:        syms,
	}

	c.predToFacts = make([][]*Fact, len(predicates))
	for i := range predicates {
		for j := range *allFacts {
			if (*allFacts)[j].Match(predicates[i]) {
				c.predToFacts[i] = append(c.predToFacts[i], &(*allFacts)[j])
			}
		}
		if len(c.predToFacts[i]) == 0 {
			myErr := &SolvSafeForWorldError{
				errMsg: fmt.Sprintf("datalog: solver error, no Facts match Pred: %s", c.symDeb.Predicate(predicates[i])),
			}
			return nil, myErr
		}
	}
	return c, nil
}

// Solve will try to find all solutions that satisfy provided current set of Facts
// against Predicates and Expressions. It's recursive and should be started with the
// the first Predicate and the non matched set of Vars
func (c *Solver) Solve(curPredInd int, currVars MatchedVariables) error {

	if curPredInd >= len(c.predicates) {
		return nil
	}
	if curPredInd == 0 && len(currVars) == 0 {
		// special case, all Preds in the query don't have Vars
		// and therefore already matched in the constructor
		return nil
	}

	pred := &c.predicates[curPredInd]
nextFact:
	for curFactInd := range c.predToFacts[curPredInd] {
		// solCadidate  is used to build a matching set of Vars for the current Fact
		solCandidate := currVars.Clone() // TODO: Can this be optimized to save memory?
		noOfTerms := len(pred.Terms)
	nextTerm:
		for j := 0; j < noOfTerms; j++ {
			id := pred.Terms[j]
			k, ok := id.(Variable)
			if !ok {
				continue nextTerm
			}
			v := c.predToFacts[curPredInd][curFactInd].Terms[j]
			if !solCandidate.Insert(k, v) {
				continue nextFact
			}
		}

		// take the Vars matched so far and continue to
		// search for a match with the next Pred & its Facts
		err := c.Solve(curPredInd+1, solCandidate)
		if err != nil {
			return err
		}
		// end of recursion for a matched Fact
		if curPredInd == len(c.predicates)-1 {
			if err = c.addIfComplete(solCandidate); err != nil {
				return err
			}
		}
	} // for - checking all current facts
	return nil
}

// addIfComplete is a helper func that will check that all the Vars of
// of all the Predicates in the Rule's body have been matched,
// it'll also apply Expressions and only then'll add the found solution to the list,
// returns expressions eval error
func (c *Solver) addIfComplete(solCandidate MatchedVariables) error {

	// TODO: Not sure if returning the map is required in Complete
	// small shallow copy here, maybe needs to be optimized
	if v := solCandidate.Complete(); v != nil {
		valid := true
		for _, e := range c.expressions {
			res, err := e.Evaluate(v, c.syms)
			if err != nil {
				return err
			}
			if !res.Equal(Bool(true)) {
				valid = false
				break
			}
		}
		if valid {
			c.solutions = append(c.solutions, v)
			return nil
		}
	}
	return nil
}
