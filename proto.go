package biscuit

import (
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/flynn/biscuit-go/datalog"
	"github.com/flynn/biscuit-go/pb"
	"github.com/flynn/biscuit-go/sig"
)

func tokenBlockToProtoBlock(input *Block) *pb.Block {
	pbFacts := make([]*pb.Fact, len(*input.facts))
	for i, fact := range *input.facts {
		pbFacts[i] = tokenFactToProtoFact(fact)
	}

	pbRules := make([]*pb.Rule, len(input.rules))
	for i, rule := range input.rules {
		pbRules[i] = tokenRuleToProtoRule(rule)
	}

	pbCaveats := make([]*pb.Caveat, len(input.caveats))
	for i, caveat := range input.caveats {
		pbCaveats[i] = tokenCaveatToProtoCaveat(caveat)
	}

	return &pb.Block{
		Index:   input.index,
		Symbols: *input.symbols,
		Facts:   pbFacts,
		Rules:   pbRules,
		Caveats: pbCaveats,
		Context: input.context,
	}
}

func protoBlockToTokenBlock(input *pb.Block) *Block {
	symbols := datalog.SymbolTable(input.Symbols)

	facts := make(datalog.FactSet, len(input.Facts))
	for i, pbFact := range input.Facts {
		facts[i] = protoFactToTokenFact(pbFact)
	}

	rules := make([]datalog.Rule, len(input.Rules))
	for i, pbRule := range input.Rules {
		rules[i] = protoRuleToTokenRule(pbRule)
	}

	caveats := make([]datalog.Caveat, len(input.Caveats))
	for i, pbCaveat := range input.Caveats {
		caveats[i] = protoCaveatToTokenCaveat(pbCaveat)
	}

	return &Block{
		index:   input.Index,
		symbols: &symbols,
		facts:   &facts,
		rules:   rules,
		caveats: caveats,
		context: input.Context,
	}
}

func tokenFactToProtoFact(input datalog.Fact) *pb.Fact {
	return &pb.Fact{
		Predicate: tokenPredicateToProtoPredicate(input.Predicate),
	}
}

func protoFactToTokenFact(input *pb.Fact) datalog.Fact {
	return datalog.Fact{
		Predicate: protoPredicateToTokenPredicate(input.Predicate),
	}
}

func tokenPredicateToProtoPredicate(input datalog.Predicate) *pb.Predicate {
	pbIds := make([]*pb.ID, len(input.IDs))
	for i, id := range input.IDs {
		pbIds[i] = tokenIDToProtoID(id)
	}

	return &pb.Predicate{
		Name: uint64(input.Name),
		Ids:  pbIds,
	}
}

func protoPredicateToTokenPredicate(input *pb.Predicate) datalog.Predicate {
	ids := make([]datalog.ID, len(input.Ids))
	for i, id := range input.Ids {
		ids[i] = protoIDToTokenID(id)
	}

	return datalog.Predicate{
		Name: datalog.Symbol(input.Name),
		IDs:  ids,
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
	case datalog.IDTypeBytes:
		pbId = &pb.ID{
			Kind:  pb.ID_BYTES,
			Bytes: input.(datalog.Bytes),
		}
	default:
		panic(fmt.Sprintf("unsupported id type: %v", input.Type()))
	}
	return pbId
}

func protoIDToTokenID(input *pb.ID) datalog.ID {
	var id datalog.ID
	switch input.Kind {
	case pb.ID_STR:
		id = datalog.String(input.Str)
	case pb.ID_DATE:
		id = datalog.Date(input.Date)
	case pb.ID_INTEGER:
		id = datalog.Integer(input.Integer)
	case pb.ID_SYMBOL:
		id = datalog.Symbol(input.Symbol)
	case pb.ID_VARIABLE:
		id = datalog.Variable(input.Variable)
	case pb.ID_BYTES:
		id = datalog.Bytes(input.Bytes)
	default:
		panic(fmt.Sprintf("unsupported id kind: %v", input.Kind))
	}

	return id
}

func tokenRuleToProtoRule(input datalog.Rule) *pb.Rule {
	pbBody := make([]*pb.Predicate, len(input.Body))
	for i, p := range input.Body {
		pbBody[i] = tokenPredicateToProtoPredicate(p)
	}

	pbConstraints := make([]*pb.Constraint, len(input.Constraints))
	for i, c := range input.Constraints {
		pbConstraints[i] = tokenConstraintToProtoConstraint(c)
	}
	return &pb.Rule{
		Head:        tokenPredicateToProtoPredicate(input.Head),
		Body:        pbBody,
		Constraints: pbConstraints,
	}
}

func protoRuleToTokenRule(input *pb.Rule) datalog.Rule {
	body := make([]datalog.Predicate, len(input.Body))
	for i, pb := range input.Body {
		body[i] = protoPredicateToTokenPredicate(pb)
	}

	constraints := make([]datalog.Constraint, len(input.Constraints))
	for i, pbConstraint := range input.Constraints {
		constraints[i] = protoConstraintToTokenConstraint(pbConstraint)
	}

	return datalog.Rule{
		Head:        protoPredicateToTokenPredicate(input.Head),
		Body:        body,
		Constraints: constraints,
	}
}

func tokenConstraintToProtoConstraint(input datalog.Constraint) *pb.Constraint {
	var pbConstraint *pb.Constraint
	switch input.Checker.(type) {
	case datalog.DateComparisonChecker:
		pbConstraint = &pb.Constraint{
			Id:   uint32(input.Name),
			Kind: pb.Constraint_DATE,
			Date: tokenDateConstraintToProtoDateConstraint(input.Checker.(datalog.DateComparisonChecker)),
		}
	case datalog.IntegerComparisonChecker:
		pbConstraint = &pb.Constraint{
			Id:   uint32(input.Name),
			Kind: pb.Constraint_INT,
			Int:  tokenIntConstraintToProtoIntConstraint(input.Checker.(datalog.IntegerComparisonChecker)),
		}
	case datalog.IntegerInChecker:
		pbConstraint = &pb.Constraint{
			Id:   uint32(input.Name),
			Kind: pb.Constraint_INT,
			Int:  tokenIntInConstraintToProtoIntConstraint(input.Checker.(datalog.IntegerInChecker)),
		}
	case datalog.StringComparisonChecker:
		pbConstraint = &pb.Constraint{
			Id:   uint32(input.Name),
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
			Id:   uint32(input.Name),
			Kind: pb.Constraint_STRING,
			Str: &pb.StringConstraint{
				Kind:  pb.StringConstraint_REGEX,
				Regex: (*regexp.Regexp)(input.Checker.(*datalog.StringRegexpChecker)).String(),
			},
		}
	case datalog.SymbolInChecker:
		pbConstraint = &pb.Constraint{
			Id:     uint32(input.Name),
			Kind:   pb.Constraint_SYMBOL,
			Symbol: tokenSymbolConstraintToProtoSymbolConstraint(input.Checker.(datalog.SymbolInChecker)),
		}
	case datalog.BytesComparisonChecker:
		pbConstraint = &pb.Constraint{
			Id:    uint32(input.Name),
			Kind:  pb.Constraint_BYTES,
			Bytes: tokenBytesConstraintToProtoBytesConstraint(input.Checker.(datalog.BytesComparisonChecker)),
		}
	case datalog.BytesInChecker:
		pbConstraint = &pb.Constraint{
			Id:    uint32(input.Name),
			Kind:  pb.Constraint_BYTES,
			Bytes: tokenBytesInConstraintToProtoBytesConstraint(input.Checker.(datalog.BytesInChecker)),
		}
	default:
		panic(fmt.Sprintf("unsupported constraint type: %v", input.Name.Type()))
	}

	return pbConstraint
}

func protoConstraintToTokenConstraint(input *pb.Constraint) datalog.Constraint {
	var constraint datalog.Constraint
	switch input.Kind {
	case pb.Constraint_DATE:
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: protoDateConstraintToTokenDateConstraint(input.Date),
		}
	case pb.Constraint_INT:
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: protoIntConstraintToTokenIntConstraint(input.Int),
		}
	case pb.Constraint_STRING:
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: protoStrConstraintToTokenStrConstraint(input.Str),
		}
	case pb.Constraint_SYMBOL:
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: protoSymbolConstraintToTokenSymbolConstraint(input.Symbol),
		}
	case pb.Constraint_BYTES:
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: protoBytesConstraintToTokenBytesConstraint(input.Bytes),
		}
	default:
		panic(fmt.Sprintf("unsupported constraint kind: %v", input.Kind))
	}

	return constraint
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

func protoDateConstraintToTokenDateConstraint(input *pb.DateConstraint) datalog.Checker {
	var checker datalog.Checker
	switch input.Kind {
	case pb.DateConstraint_BEFORE:
		checker = datalog.DateComparisonChecker{
			Comparison: datalog.DateComparisonBefore,
			Date:       datalog.Date(input.Before),
		}
	case pb.DateConstraint_AFTER:
		checker = datalog.DateComparisonChecker{
			Comparison: datalog.DateComparisonAfter,
			Date:       datalog.Date(input.After),
		}
	default:
		panic(fmt.Sprintf("unsupported date constraint kind: %v", input.Kind))
	}
	return checker
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

func protoIntConstraintToTokenIntConstraint(input *pb.IntConstraint) datalog.Checker {
	var checker datalog.Checker
	switch input.Kind {
	case pb.IntConstraint_EQUAL:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonEqual,
			Integer:    datalog.Integer(input.Equal),
		}
	case pb.IntConstraint_IN:
		set := make(map[datalog.Integer]struct{}, len(input.InSet))
		for _, i := range input.InSet {
			set[datalog.Integer(i)] = struct{}{}
		}
		checker = datalog.IntegerInChecker{
			Set: set,
			Not: false,
		}
	case pb.IntConstraint_NOT_IN:
		set := make(map[datalog.Integer]struct{}, len(input.NotInSet))
		for _, i := range input.InSet {
			set[datalog.Integer(i)] = struct{}{}
		}
		checker = datalog.IntegerInChecker{
			Set: set,
			Not: true,
		}
	case pb.IntConstraint_LARGER:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonGT,
			Integer:    datalog.Integer(input.Larger),
		}
	case pb.IntConstraint_LARGER_OR_EQUAL:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonGTE,
			Integer:    datalog.Integer(input.LargerOrEqual),
		}
	case pb.IntConstraint_LOWER:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonLT,
			Integer:    datalog.Integer(input.Lower),
		}
	case pb.IntConstraint_LOWER_OR_EQUAL:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonLTE,
			Integer:    datalog.Integer(input.LowerOrEqual),
		}
	default:
		panic(fmt.Sprintf("unsupported int constraint kind: %v", input.Kind))
	}
	return checker
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

func protoStrConstraintToTokenStrConstraint(input *pb.StringConstraint) datalog.Checker {
	var checker datalog.Checker
	switch input.Kind {
	case pb.StringConstraint_EQUAL:
		checker = datalog.StringComparisonChecker{
			Comparison: datalog.StringComparisonEqual,
			Str:        datalog.String(input.Equal),
		}
	case pb.StringConstraint_IN:
		set := make(map[datalog.String]struct{}, len(input.InSet))
		for _, s := range input.InSet {
			set[datalog.String(s)] = struct{}{}
		}
		checker = datalog.StringInChecker{
			Set: set,
			Not: false,
		}
	case pb.StringConstraint_NOT_IN:
		set := make(map[datalog.String]struct{}, len(input.NotInSet))
		for _, s := range input.InSet {
			set[datalog.String(s)] = struct{}{}
		}
		checker = datalog.StringInChecker{
			Set: set,
			Not: true,
		}
	case pb.StringConstraint_PREFIX:
		checker = datalog.StringComparisonChecker{
			Comparison: datalog.StringComparisonPrefix,
			Str:        datalog.String(input.Prefix),
		}
	case pb.StringConstraint_REGEX:
		re := datalog.StringRegexpChecker(*regexp.MustCompile(input.Regex))
		checker = &re
	case pb.StringConstraint_SUFFIX:
		checker = datalog.StringComparisonChecker{
			Comparison: datalog.StringComparisonSuffix,
			Str:        datalog.String(input.Suffix),
		}
	default:
		panic(fmt.Sprintf("unsupported string constraint king: %v", input.Kind))
	}

	return checker
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

func protoSymbolConstraintToTokenSymbolConstraint(input *pb.SymbolConstraint) datalog.Checker {
	var checker datalog.Checker
	switch input.Kind {
	case pb.SymbolConstraint_IN:
		set := make(map[datalog.Symbol]struct{}, len(input.InSet))
		for _, s := range input.InSet {
			set[datalog.Symbol(s)] = struct{}{}
		}
		checker = datalog.SymbolInChecker{
			Set: set,
			Not: false,
		}
	case pb.SymbolConstraint_NOT_IN:
		set := make(map[datalog.Symbol]struct{}, len(input.NotInSet))
		for _, s := range input.NotInSet {
			set[datalog.Symbol(s)] = struct{}{}
		}
		checker = datalog.SymbolInChecker{
			Set: set,
			Not: true,
		}
	default:
		panic(fmt.Sprintf("unsupported symbol constraint kind: %v", input.Kind))
	}
	return checker
}

func tokenBytesConstraintToProtoBytesConstraint(input datalog.BytesComparisonChecker) *pb.BytesConstraint {
	var pbBytesConstraint *pb.BytesConstraint
	switch input.Comparison {
	case datalog.BytesComparisonEqual:
		pbBytesConstraint = &pb.BytesConstraint{
			Kind:  pb.BytesConstraint_EQUAL,
			Equal: input.Bytes,
		}
	default:
		panic(fmt.Sprintf("unsupported bytes comparison: %v", input.Comparison))
	}

	return pbBytesConstraint
}

func tokenBytesInConstraintToProtoBytesConstraint(input datalog.BytesInChecker) *pb.BytesConstraint {
	var pbBytesConstraint *pb.BytesConstraint
	pbSet := make([][]byte, 0, len(input.Set))
	for e := range input.Set {
		b, err := hex.DecodeString(e)
		if err != nil {
			panic(fmt.Sprintf("failed to decode hex string %q: %v", e, err))
		}
		pbSet = append(pbSet, b)
	}

	if input.Not {
		pbBytesConstraint = &pb.BytesConstraint{
			Kind:     pb.BytesConstraint_NOT_IN,
			NotInSet: pbSet,
		}
	} else {
		pbBytesConstraint = &pb.BytesConstraint{
			Kind:  pb.BytesConstraint_IN,
			InSet: pbSet,
		}
	}

	return pbBytesConstraint
}

func protoBytesConstraintToTokenBytesConstraint(input *pb.BytesConstraint) datalog.Checker {
	var checker datalog.Checker
	switch input.Kind {
	case pb.BytesConstraint_EQUAL:
		checker = datalog.BytesComparisonChecker{
			Comparison: datalog.BytesComparisonEqual,
			Bytes:      input.Equal,
		}
	case pb.BytesConstraint_IN:
		set := make(map[string]struct{}, len(input.InSet))
		for _, s := range input.InSet {
			set[string(s)] = struct{}{}
		}
		checker = datalog.BytesInChecker{
			Set: set,
			Not: false,
		}
	case pb.BytesConstraint_NOT_IN:
		set := make(map[string]struct{}, len(input.NotInSet))
		for _, s := range input.InSet {
			set[string(s)] = struct{}{}
		}
		checker = datalog.BytesInChecker{
			Set: set,
			Not: true,
		}
	default:
		panic(fmt.Sprintf("unsupported bytes constraint kind: %v", input.Kind))
	}

	return checker
}

func tokenSignatureToProtoSignature(ts *sig.TokenSignature) *pb.Signature {
	params, z := ts.Encode()
	return &pb.Signature{
		Parameters: params,
		Z:          z,
	}
}

func protoSignatureToTokenSignature(ps *pb.Signature) (*sig.TokenSignature, error) {
	return sig.Decode(ps.Parameters, ps.Z)
}

func tokenCaveatToProtoCaveat(input datalog.Caveat) *pb.Caveat {
	pbQueries := make([]*pb.Rule, len(input.Queries))
	for i, query := range input.Queries {
		pbQueries[i] = tokenRuleToProtoRule(query)
	}

	return &pb.Caveat{
		Queries: pbQueries,
	}
}

func protoCaveatToTokenCaveat(input *pb.Caveat) datalog.Caveat {
	queries := make([]datalog.Rule, len(input.Queries))
	for i, query := range input.Queries {
		queries[i] = protoRuleToTokenRule(query)
	}

	return datalog.Caveat{
		Queries: queries,
	}
}
