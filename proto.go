package biscuit

import (
	"fmt"
	"regexp"

	"github.com/flynn/biscuit-go/datalog"
	"github.com/flynn/biscuit-go/pb"
	"github.com/flynn/biscuit-go/sig"
)

func tokenBlockToProtoBlock(input *Block) *pb.Block {
	var pbFacts []*pb.Fact
	for _, fact := range *input.facts {
		pbFacts = append(pbFacts, tokenFactToProtoFact(fact))
	}

	var pbRules []*pb.Rule
	for _, rule := range input.rules {
		pbRules = append(pbRules, tokenRuleToProtoRule(rule))
	}

	return &pb.Block{
		Index:   uint32(input.index),
		Symbols: *input.symbols,
		Facts:   pbFacts,
		Rules:   pbRules,
	}
}

func tokenFactToProtoFact(input datalog.Fact) *pb.Fact {
	return &pb.Fact{
		Predicate: tokenPredicateToProtoPredicate(input.Predicate),
	}
}

func tokenPredicateToProtoPredicate(input datalog.Predicate) *pb.Predicate {
	var pbIds []*pb.ID
	for _, id := range input.IDs {
		pbIds = append(pbIds, tokenIDToProtoID(id))
	}

	return &pb.Predicate{
		Name: uint64(input.Name),
		Ids:  pbIds,
	}
}

func tokenIDToProtoID(input datalog.ID) *pb.ID {
	var pbId *pb.ID
	switch input.Type() {
	case datalog.IDTypeString:
		pbId = &pb.ID{
			Kind: pb.ID_STR,
			Str:  string(input.(datalog.String)),
		}
	case datalog.IDTypeDate:
		pbId = &pb.ID{
			Kind: pb.ID_DATE,
			Date: uint64(input.(datalog.Date)),
		}
	case datalog.IDTypeInteger:
		pbId = &pb.ID{
			Kind:    pb.ID_INTEGER,
			Integer: int64(input.(datalog.Integer)),
		}
	case datalog.IDTypeSymbol:
		pbId = &pb.ID{
			Kind:   pb.ID_SYMBOL,
			Symbol: uint64(input.(datalog.Symbol)),
		}
	case datalog.IDTypeVariable:
		pbId = &pb.ID{
			Kind:     pb.ID_VARIABLE,
			Variable: uint32(input.(datalog.Variable)),
		}
	default:
		panic(fmt.Sprintf("unsupported id type: %v", input.Type()))
	}
	return pbId
}

func tokenRuleToProtoRule(input *datalog.Rule) *pb.Rule {
	var pbBody []*pb.Predicate
	for _, p := range input.Body {
		pbBody = append(pbBody, tokenPredicateToProtoPredicate(p))
	}

	var pbConstraints []*pb.Constraint
	for _, c := range input.Constraints {
		pbConstraints = append(pbConstraints, tokenConstraintToProtoConstraint(c))
	}
	return &pb.Rule{
		Head:        tokenPredicateToProtoPredicate(input.Head),
		Body:        pbBody,
		Constraints: pbConstraints,
	}
}

func tokenConstraintToProtoConstraint(input datalog.Constraint) *pb.Constraint {
	var pbConstraint *pb.Constraint

	switch input.Name.Type() {
	case datalog.IDTypeDate:
		pbConstraint = &pb.Constraint{
			Kind: pb.Constraint_DATE,
			Date: tokenDateConstraintToProtoDateConstraint(input.Checker.(datalog.DateComparisonChecker)),
		}
	case datalog.IDTypeInteger:
		switch input.Checker.(type) {
		case datalog.IntegerComparisonChecker:
			pbConstraint = &pb.Constraint{
				Kind: pb.Constraint_INT,
				Int:  tokenIntConstraintToProtoIntConstraint(input.Checker.(datalog.IntegerComparisonChecker)),
			}
		case datalog.IntegerInChecker:
			pbConstraint = &pb.Constraint{
				Kind: pb.Constraint_INT,
				Int:  tokenIntInConstraintToProtoIntConstraint(input.Checker.(datalog.IntegerInChecker)),
			}
		}
	case datalog.IDTypeString:
		switch input.Checker.(type) {
		case datalog.StringComparisonChecker:
			pbConstraint = &pb.Constraint{
				Kind: pb.Constraint_STRING,
				Str:  tokenStrConstraintToProtoStrConstraint(input.Checker.(datalog.StringComparisonChecker)),
			}
		case datalog.StringInChecker:
			pbConstraint = &pb.Constraint{
				Kind: pb.Constraint_STRING,
				Str:  tokenStrInConstraintToProtoStrConstraint(input.Checker.(datalog.StringInChecker)),
			}
		case *datalog.StringRegexpChecker:
			pbConstraint = &pb.Constraint{
				Kind: pb.Constraint_STRING,
				Str: &pb.StringConstraint{
					Kind:  pb.StringConstraint_REGEX,
					Regex: (*regexp.Regexp)(input.Checker.(*datalog.StringRegexpChecker)).String(),
				},
			}
		}

	case datalog.IDTypeSymbol:
		pbConstraint = &pb.Constraint{
			Kind:   pb.Constraint_SYMBOL,
			Symbol: tokenSymbolConstraintToProtoSymbolConstraint(input.Checker.(datalog.SymbolInChecker)),
		}
	default:
		panic(fmt.Sprintf("unsupported constraint type: %v", input.Name.Type()))
	}

	return pbConstraint
}

func tokenDateConstraintToProtoDateConstraint(input datalog.DateComparisonChecker) *pb.DateConstraint {
	var pbDateConstraint *pb.DateConstraint
	switch input.Comparison {
	case datalog.DateComparisonBefore:
		pbDateConstraint = &pb.DateConstraint{
			Kind:   pb.DateConstraint_BEFORE,
			Before: uint64(input.Date),
		}
	case datalog.DateComparisonAfter:
		pbDateConstraint = &pb.DateConstraint{
			Kind:  pb.DateConstraint_AFTER,
			After: uint64(input.Date),
		}
	default:
		panic(fmt.Sprintf("unsupported date constraint: %v", input.Comparison))
	}

	return pbDateConstraint
}

func tokenIntConstraintToProtoIntConstraint(input datalog.IntegerComparisonChecker) *pb.IntConstraint {
	var pbIntConstraint *pb.IntConstraint
	switch input.Comparison {
	case datalog.IntegerComparisonEqual:
		pbIntConstraint = &pb.IntConstraint{
			Kind:  pb.IntConstraint_EQUAL,
			Equal: int64(input.Integer),
		}
	case datalog.IntegerComparisonGT:
		pbIntConstraint = &pb.IntConstraint{
			Kind:   pb.IntConstraint_LARGER,
			Larger: int64(input.Integer),
		}
	case datalog.IntegerComparisonGTE:
		pbIntConstraint = &pb.IntConstraint{
			Kind:          pb.IntConstraint_LARGER_OR_EQUAL,
			LargerOrEqual: int64(input.Integer),
		}
	case datalog.IntegerComparisonLT:
		pbIntConstraint = &pb.IntConstraint{
			Kind:  pb.IntConstraint_LOWER,
			Lower: int64(input.Integer),
		}
	case datalog.IntegerComparisonLTE:
		pbIntConstraint = &pb.IntConstraint{
			Kind:         pb.IntConstraint_LOWER_OR_EQUAL,
			LowerOrEqual: int64(input.Integer),
		}
	default:
		panic(fmt.Sprintf("unsupported int constraint: %v", input.Comparison))
	}
	return pbIntConstraint
}

func tokenIntInConstraintToProtoIntConstraint(input datalog.IntegerInChecker) *pb.IntConstraint {
	var pbIntConstraint *pb.IntConstraint

	pbSet := make([]int64, 0, len(input.Set))
	for e := range input.Set {
		pbSet = append(pbSet, int64(e))
	}

	if input.Not {
		pbIntConstraint = &pb.IntConstraint{
			Kind:     pb.IntConstraint_NOT_IN,
			NotInSet: pbSet,
		}
	} else {
		pbIntConstraint = &pb.IntConstraint{
			Kind:  pb.IntConstraint_IN,
			InSet: pbSet,
		}
	}
	return pbIntConstraint
}

func tokenStrConstraintToProtoStrConstraint(input datalog.StringComparisonChecker) *pb.StringConstraint {
	var pbStrConstraint *pb.StringConstraint
	switch input.Comparison {
	case datalog.StringComparisonEqual:
		pbStrConstraint = &pb.StringConstraint{
			Kind:  pb.StringConstraint_EQUAL,
			Equal: string(input.Str),
		}
	case datalog.StringComparisonPrefix:
		pbStrConstraint = &pb.StringConstraint{
			Kind:   pb.StringConstraint_PREFIX,
			Prefix: string(input.Str),
		}
	case datalog.StringComparisonSuffix:
		pbStrConstraint = &pb.StringConstraint{
			Kind:   pb.StringConstraint_SUFFIX,
			Suffix: string(input.Str),
		}
	default:
		panic(fmt.Sprintf("unsupported string constraint: %v", input.Comparison))
	}
	return pbStrConstraint
}

func tokenStrInConstraintToProtoStrConstraint(input datalog.StringInChecker) *pb.StringConstraint {
	var pbStringConstraint *pb.StringConstraint

	pbSet := make([]string, 0, len(input.Set))
	for e := range input.Set {
		pbSet = append(pbSet, string(e))
	}

	if input.Not {
		pbStringConstraint = &pb.StringConstraint{
			Kind:     pb.StringConstraint_NOT_IN,
			NotInSet: pbSet,
		}
	} else {
		pbStringConstraint = &pb.StringConstraint{
			Kind:  pb.StringConstraint_IN,
			InSet: pbSet,
		}
	}
	return pbStringConstraint
}

func tokenSymbolConstraintToProtoSymbolConstraint(input datalog.SymbolInChecker) *pb.SymbolConstraint {
	var pbSymbolConstraint *pb.SymbolConstraint

	pbSet := make([]uint64, 0, len(input.Set))
	for e := range input.Set {
		pbSet = append(pbSet, uint64(e))
	}

	if input.Not {
		pbSymbolConstraint = &pb.SymbolConstraint{
			Kind:     pb.SymbolConstraint_NOT_IN,
			NotInSet: pbSet,
		}
	} else {
		pbSymbolConstraint = &pb.SymbolConstraint{
			Kind:  pb.SymbolConstraint_IN,
			InSet: pbSet,
		}
	}
	return pbSymbolConstraint
}

func tokenSignatureToProtoSignature(ts *sig.TokenSignature) *pb.Signature {
	var protoParams [][]byte
	for _, p := range ts.Params {
		protoParams = append(protoParams, p.Encode([]byte{}))
	}
	return &pb.Signature{
		Parameters: protoParams,
		Z:          ts.Z.Encode([]byte{}),
	}
}
