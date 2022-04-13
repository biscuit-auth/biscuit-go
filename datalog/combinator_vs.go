package datalog

import (
	"fmt"
)

// SolvSafeForWorldError allows to make an error that will not cause
// failed state while Authoriser reconciles the facts using rules
type SolvSafeForWorldError struct {
	diagMsg string
}

func (e SolvSafeForWorldError) Error() string {
	return e.diagMsg
}

func (e SolvSafeForWorldError) Is(target error) bool {
	if _, ok := target.(*SolvSafeForWorldError); ok {
		return true
	}
	return false
}

type CombinatorVS struct {
	predicates  []Predicate
	expressions []Expression
	allFacts    *FactSet
	//	currentFacts *FactSet
	predToFacts [][]*Fact
	solutions   []MatchedVariables
	symDeb      SymbolDebugger
	syms        *SymbolTable
}

func NewCombinatorVS(predicates []Predicate, expressions []Expression, allFacts *FactSet, syms *SymbolTable) (*CombinatorVS, error) {
	c := &CombinatorVS{
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
				diagMsg: fmt.Sprintf("datalog: solver error, no Facts match Pred: %s", c.symDeb.Predicate(predicates[i])),
			}
			return nil, myErr
		}
	}
	return c, nil
}

func (c *CombinatorVS) Solve(startPredInd int, currVars MatchedVariables) error {

	if startPredInd >= len(c.predicates) {
		return nil
	}
	if startPredInd == 0 && len(currVars) == 0 {
		// special case, all Preds in the query don't have Vars
		// and therefore already matched in the constructor
		return nil
	}

	// This loop allows us to deal with Contraints, i.e. the Predicates that don't have any Var Terms
	// recursion is only used for Predicates that have at least one Variable
	//nextPred:
	//	for curPredInd := startPredInd; curPredInd < len(c.predicates); curPredInd++ {
	curPredInd := startPredInd
	pred := &c.predicates[curPredInd]
	//predHasVars := false // TODO: Remove, no longer needed
nextFact:
	for curFactInd := range c.predToFacts[curPredInd] {
		// solCadidate  is used to build a matching set of Vars for the current Fact
		solCandidate := currVars.Clone() // TODO: Can this be optimized to save memory?
		//matchIDs := true                 // non var preds are pre-matched
		noOfTerms := len(pred.Terms)
	nextTerm:
		for j := 0; j < noOfTerms; j++ {
			id := pred.Terms[j]
			/*
				switch k, ok := id.(Variable); ok {
				case false:
					continue nextTerm // look for Terms that are Vars
				default:
					predHasVars = true
					v := c.predToFacts[curPredInd][curFactInd].Terms[j]
					if !solCandidate.Insert(k, v) {
						matchIDs = false
						continue nextFact
					}
					//matchIDs = true
				}
			*/
			k, ok := id.(Variable)
			if !ok {
				continue nextTerm
			}
			//predHasVars = true
			v := c.predToFacts[curPredInd][curFactInd].Terms[j]
			if !solCandidate.Insert(k, v) {
				//matchIDs = false
				continue nextFact
			}
		}

		//if !matchIDs {
		// if the current Pred has no variables, check the next one
		/*
			if !predHasVars { // TODO: Remove we should never get here now
				continue nextPred
			}
		*/
		/*
			if curPredInd == len(c.predicates)-1 && curFactInd == len(c.predToFacts[curPredInd])-1 {
				return fmt.Errorf("datalog error, solver can't match a Var")
			}
		*/
		// continue to check the current facts
		// possibly not all vars of the current pred are matched
		//	continue
		//}

		// take the matched Vars and check it with the next Pred & its Facts
		err := c.Solve(curPredInd+1, solCandidate)
		if err != nil {
			return err
		}
		if curPredInd == len(c.predicates)-1 {
			_, err = c.AddIfComplete(solCandidate)
			if err != nil {
				return err
			}
		}
		/*
			// this is either the last recursion call or there was only 1 predicate
			// Could this happen??
			if curPredInd == len(c.predicates)-1 && curFactInd == len(c.predToFacts[curPredInd])-1 {
				if !done && len(c.solutions) == 0 {
					return fmt.Errorf("datalog error, solver didn't find a solution")
				}
				return nil
			}
		*/
	} // for - checking all current facts
	/*
		// all facts and possible solutions for the current Pred have been checked
		// there should be no need to check new predicates
		// this loop will make a cycle above, i.e. select a the next pred to check, if current pred doesn't have any Vars.
		if predHasVars {
			break
		}
	*/
	//} // checked all predicates
	return nil
}

func (c *CombinatorVS) AddIfComplete(solCandidate MatchedVariables) (bool, error) {

	// TODO: Not sure if returning the map is required in Complete
	// small shallow copy here, maybe needs to be optimized
	if v := solCandidate.Complete(); v != nil {
		valid := true
		for _, e := range c.expressions {
			res, err := e.Evaluate(v, c.syms)
			if err != nil {
				return true, err
			}
			if !res.Equal(Bool(true)) {
				valid = false
				break
			}
		}
		if valid {
			c.solutions = append(c.solutions, v)
			return true, nil
		}
	}
	return false, nil
}

func (r Rule) Apply2(facts *FactSet, newFacts *FactSet, syms *SymbolTable) error {
	// extract all variables from the rule body
	variables := make(MatchedVariables)
	for _, p := range r.Body {
		for _, id := range p.Terms {
			v, ok := id.(Variable)
			if !ok {
				continue
			}
			variables[v] = nil
		}
	}

	comb, err := NewCombinatorVS(r.Body, r.Expressions, facts, syms)
	if err != nil {
		return err
	}
	err = comb.Solve(0, variables)
	if err != nil {
		return err
	}
	if len(comb.solutions) == 0 {
		switch len(variables) {
		case 0:
			// special case, query with Facts
			return nil
		default:
			myErr := &SolvSafeForWorldError{
				diagMsg: "datalog: solver didn't find a matching solution",
			}
			return myErr
		}
	}
outer:
	for _, h := range comb.solutions {
		p := r.Head.Clone()
		for i, id := range p.Terms {
			k, ok := id.(Variable)
			if !ok {
				continue
			}
			v, ok := h[k]
			if !ok {
				return InvalidRuleError{r, k}
			}

			// prevent the rule from generating facts with forbidden IDs
			for _, f := range r.forbiddenIDs {
				if f.Equal(*v) {
					continue outer
				}
			}

			p.Terms[i] = *v
		}
		newFacts.Insert(Fact{p})
	}

	return nil
}

func (w *World) QueryRule2(rule Rule, syms *SymbolTable) (*FactSet, error) {
	newFacts := &FactSet{}
	return newFacts, rule.Apply2(w.facts, newFacts, syms)
}
