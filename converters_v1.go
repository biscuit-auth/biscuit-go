package biscuit

import (
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/flynn/biscuit-go/datalog"
	"github.com/flynn/biscuit-go/pb"
)

func tokenFactToProtoFactV1(input datalog.Fact) (*pb.FactV1, error) {
	pred, err := tokenPredicateToProtoPredicateV1(input.Predicate)
	if err != nil {
		return nil, err
	}

	return &pb.FactV1{
		Predicate: pred,
	}, nil
}

func protoFactToTokenFactV1(input *pb.FactV1) (*datalog.Fact, error) {
	pred, err := protoPredicateToTokenPredicateV1(input.Predicate)
	if err != nil {
		return nil, err
	}
	return &datalog.Fact{
		Predicate: *pred,
	}, nil
}

func tokenPredicateToProtoPredicateV1(input datalog.Predicate) (*pb.PredicateV1, error) {
	pbIds := make([]*pb.IDV1, len(input.IDs))
	var err error
	for i, id := range input.IDs {
		pbIds[i], err = tokenIDToProtoIDV1(id)
		if err != nil {
			return nil, err
		}
	}

	return &pb.PredicateV1{
		Name: uint64(input.Name),
		Ids:  pbIds,
	}, nil
}

func protoPredicateToTokenPredicateV1(input *pb.PredicateV1) (*datalog.Predicate, error) {
	ids := make([]datalog.ID, len(input.Ids))
	for i, id := range input.Ids {
		dlid, err := protoIDToTokenIDV1(id)
		if err != nil {
			return nil, err
		}

		ids[i] = *dlid
	}

	return &datalog.Predicate{
		Name: datalog.Symbol(input.Name),
		IDs:  ids,
	}, nil
}

func tokenIDToProtoIDV1(input datalog.ID) (*pb.IDV1, error) {
	var pbId *pb.IDV1
	switch input.Type() {
	case datalog.IDTypeString:
		pbId = &pb.IDV1{
			Kind: pb.IDV1_STR,
			Str:  string(input.(datalog.String)),
		}
	case datalog.IDTypeDate:
		pbId = &pb.IDV1{
			Kind: pb.IDV1_DATE,
			Date: uint64(input.(datalog.Date)),
		}
	case datalog.IDTypeInteger:
		pbId = &pb.IDV1{
			Kind:    pb.IDV1_INTEGER,
			Integer: int64(input.(datalog.Integer)),
		}
	case datalog.IDTypeSymbol:
		pbId = &pb.IDV1{
			Kind:   pb.IDV1_SYMBOL,
			Symbol: uint64(input.(datalog.Symbol)),
		}
	case datalog.IDTypeVariable:
		pbId = &pb.IDV1{
			Kind:     pb.IDV1_VARIABLE,
			Variable: uint32(input.(datalog.Variable)),
		}
	case datalog.IDTypeBytes:
		pbId = &pb.IDV1{
			Kind:  pb.IDV1_BYTES,
			Bytes: input.(datalog.Bytes),
		}
	case datalog.IDTypeSet:
		datalogSet := input.(datalog.Set)
		protoSet := make([]*pb.IDV1, 0, len(datalogSet))
		for _, datalogElt := range datalogSet {
			protoElt, err := tokenIDToProtoIDV1(datalogElt)
			if err != nil {
				return nil, err
			}
			protoSet = append(protoSet, protoElt)
		}
		pbId = &pb.IDV1{
			Kind: pb.IDV1_SET,
			Set:  protoSet,
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported id type: %v", input.Type())
	}
	return pbId, nil
}

func protoIDToTokenIDV1(input *pb.IDV1) (*datalog.ID, error) {
	var id datalog.ID
	switch input.Kind {
	case pb.IDV1_STR:
		id = datalog.String(input.Str)
	case pb.IDV1_DATE:
		id = datalog.Date(input.Date)
	case pb.IDV1_INTEGER:
		id = datalog.Integer(input.Integer)
	case pb.IDV1_SYMBOL:
		id = datalog.Symbol(input.Symbol)
	case pb.IDV1_VARIABLE:
		id = datalog.Variable(input.Variable)
	case pb.IDV1_BYTES:
		id = datalog.Bytes(input.Bytes)
	case pb.IDV1_SET:
		datalogSet := make(datalog.Set, 0, len(input.Set))
		for _, protoElt := range input.Set {
			datalogElt, err := protoIDToTokenIDV1(protoElt)
			if err != nil {
				return nil, err
			}
			datalogSet = append(datalogSet, *datalogElt)
		}
		id = datalogSet
	default:
		return nil, fmt.Errorf("biscuit: unsupported id kind: %v", input.Kind)
	}

	return &id, nil
}

func tokenRuleToProtoRuleV1(input datalog.Rule) (*pb.RuleV1, error) {
	pbBody := make([]*pb.PredicateV1, len(input.Body))
	for i, p := range input.Body {
		pred, err := tokenPredicateToProtoPredicateV1(p)
		if err != nil {
			return nil, err
		}
		pbBody[i] = pred
	}

	pbConstraints := make([]*pb.ConstraintV1, len(input.Constraints))
	for i, c := range input.Constraints {
		cons, err := tokenConstraintToProtoConstraintV1(c)
		if err != nil {
			return nil, err
		}
		pbConstraints[i] = cons
	}

	pbHead, err := tokenPredicateToProtoPredicateV1(input.Head)
	if err != nil {
		return nil, err
	}

	return &pb.RuleV1{
		Head:        pbHead,
		Body:        pbBody,
		Constraints: pbConstraints,
	}, nil
}

func protoRuleToTokenRuleV1(input *pb.RuleV1) (*datalog.Rule, error) {
	body := make([]datalog.Predicate, len(input.Body))
	for i, pb := range input.Body {
		b, err := protoPredicateToTokenPredicateV1(pb)
		if err != nil {
			return nil, err
		}
		body[i] = *b
	}

	constraints := make([]datalog.Constraint, len(input.Constraints))
	for i, pbConstraint := range input.Constraints {
		c, err := protoConstraintToTokenConstraintV1(pbConstraint)
		if err != nil {
			return nil, err
		}
		constraints[i] = *c
	}

	head, err := protoPredicateToTokenPredicateV1(input.Head)
	if err != nil {
		return nil, err
	}
	return &datalog.Rule{
		Head:        *head,
		Body:        body,
		Constraints: constraints,
	}, nil
}

func tokenConstraintToProtoConstraintV1(input datalog.Constraint) (*pb.ConstraintV1, error) {
	var pbConstraint *pb.ConstraintV1
	switch input.Checker.(type) {
	case datalog.DateComparisonChecker:
		c, err := tokenDateConstraintToProtoDateConstraintV1(input.Checker.(datalog.DateComparisonChecker))
		if err != nil {
			return nil, err
		}
		pbConstraint = &pb.ConstraintV1{
			Id:   uint32(input.Name),
			Kind: pb.ConstraintV1_DATE,
			Date: c,
		}
	case datalog.IntegerComparisonChecker:
		c, err := tokenIntConstraintToProtoIntConstraintV1(input.Checker.(datalog.IntegerComparisonChecker))
		if err != nil {
			return nil, err
		}
		pbConstraint = &pb.ConstraintV1{
			Id:   uint32(input.Name),
			Kind: pb.ConstraintV1_INT,
			Int:  c,
		}
	case datalog.IntegerInChecker:
		pbConstraint = &pb.ConstraintV1{
			Id:   uint32(input.Name),
			Kind: pb.ConstraintV1_INT,
			Int:  tokenIntInConstraintToProtoIntConstraintV1(input.Checker.(datalog.IntegerInChecker)),
		}
	case datalog.StringComparisonChecker:
		c, err := tokenStrConstraintToProtoStrConstraintV1(input.Checker.(datalog.StringComparisonChecker))
		if err != nil {
			return nil, err
		}
		pbConstraint = &pb.ConstraintV1{
			Id:   uint32(input.Name),
			Kind: pb.ConstraintV1_STRING,
			Str:  c,
		}
	case datalog.StringInChecker:
		pbConstraint = &pb.ConstraintV1{
			Id:   uint32(input.Name),
			Kind: pb.ConstraintV1_STRING,
			Str:  tokenStrInConstraintToProtoStrConstraintV1(input.Checker.(datalog.StringInChecker)),
		}
	case *datalog.StringRegexpChecker:
		pbConstraint = &pb.ConstraintV1{
			Id:   uint32(input.Name),
			Kind: pb.ConstraintV1_STRING,
			Str: &pb.StringConstraintV1{
				Kind:  pb.StringConstraintV1_REGEX,
				Regex: (*regexp.Regexp)(input.Checker.(*datalog.StringRegexpChecker)).String(),
			},
		}
	case datalog.SymbolInChecker:
		pbConstraint = &pb.ConstraintV1{
			Id:     uint32(input.Name),
			Kind:   pb.ConstraintV1_SYMBOL,
			Symbol: tokenSymbolConstraintToProtoSymbolConstraintV1(input.Checker.(datalog.SymbolInChecker)),
		}
	case datalog.BytesComparisonChecker:
		c, err := tokenBytesConstraintToProtoBytesConstraintV1(input.Checker.(datalog.BytesComparisonChecker))
		if err != nil {
			return nil, err
		}
		pbConstraint = &pb.ConstraintV1{
			Id:    uint32(input.Name),
			Kind:  pb.ConstraintV1_BYTES,
			Bytes: c,
		}
	case datalog.BytesInChecker:
		c, err := tokenBytesInConstraintToProtoBytesConstraintV1(input.Checker.(datalog.BytesInChecker))
		if err != nil {
			return nil, err
		}
		pbConstraint = &pb.ConstraintV1{
			Id:    uint32(input.Name),
			Kind:  pb.ConstraintV1_BYTES,
			Bytes: c,
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported constraint type: %v", input.Name.Type())
	}

	return pbConstraint, nil
}

func protoConstraintToTokenConstraintV1(input *pb.ConstraintV1) (*datalog.Constraint, error) {
	var constraint datalog.Constraint
	switch input.Kind {
	case pb.ConstraintV1_DATE:
		c, err := protoDateConstraintToTokenDateConstraintV1(input.Date)
		if err != nil {
			return nil, err
		}
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: *c,
		}
	case pb.ConstraintV1_INT:
		c, err := protoIntConstraintToTokenIntConstraintV1(input.Int)
		if err != nil {
			return nil, err
		}
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: *c,
		}
	case pb.ConstraintV1_STRING:
		c, err := protoStrConstraintToTokenStrConstraintV1(input.Str)
		if err != nil {
			return nil, err
		}
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: *c,
		}
	case pb.ConstraintV1_SYMBOL:
		c, err := protoSymbolConstraintToTokenSymbolConstraintV1(input.Symbol)
		if err != nil {
			return nil, err
		}
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: *c,
		}
	case pb.ConstraintV1_BYTES:
		c, err := protoBytesConstraintToTokenBytesConstraintV1(input.Bytes)
		if err != nil {
			return nil, err
		}
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: *c,
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported constraint kind: %v", input.Kind)
	}

	return &constraint, nil
}

func tokenDateConstraintToProtoDateConstraintV1(input datalog.DateComparisonChecker) (*pb.DateConstraintV1, error) {
	var pbDateConstraint *pb.DateConstraintV1
	switch input.Comparison {
	case datalog.DateComparisonBefore:
		pbDateConstraint = &pb.DateConstraintV1{
			Kind:   pb.DateConstraintV1_BEFORE,
			Before: uint64(input.Date),
		}
	case datalog.DateComparisonAfter:
		pbDateConstraint = &pb.DateConstraintV1{
			Kind:  pb.DateConstraintV1_AFTER,
			After: uint64(input.Date),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported date constraint: %v", input.Comparison)
	}

	return pbDateConstraint, nil
}

func protoDateConstraintToTokenDateConstraintV1(input *pb.DateConstraintV1) (*datalog.Checker, error) {
	var checker datalog.Checker
	switch input.Kind {
	case pb.DateConstraintV1_BEFORE:
		checker = datalog.DateComparisonChecker{
			Comparison: datalog.DateComparisonBefore,
			Date:       datalog.Date(input.Before),
		}
	case pb.DateConstraintV1_AFTER:
		checker = datalog.DateComparisonChecker{
			Comparison: datalog.DateComparisonAfter,
			Date:       datalog.Date(input.After),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported date constraint kind: %v", input.Kind)
	}
	return &checker, nil
}

func tokenIntConstraintToProtoIntConstraintV1(input datalog.IntegerComparisonChecker) (*pb.IntConstraintV1, error) {
	var pbIntConstraint *pb.IntConstraintV1
	switch input.Comparison {
	case datalog.IntegerComparisonEqual:
		pbIntConstraint = &pb.IntConstraintV1{
			Kind:  pb.IntConstraintV1_EQUAL,
			Equal: int64(input.Integer),
		}
	case datalog.IntegerComparisonGT:
		pbIntConstraint = &pb.IntConstraintV1{
			Kind:   pb.IntConstraintV1_LARGER,
			Larger: int64(input.Integer),
		}
	case datalog.IntegerComparisonGTE:
		pbIntConstraint = &pb.IntConstraintV1{
			Kind:          pb.IntConstraintV1_LARGER_OR_EQUAL,
			LargerOrEqual: int64(input.Integer),
		}
	case datalog.IntegerComparisonLT:
		pbIntConstraint = &pb.IntConstraintV1{
			Kind:  pb.IntConstraintV1_LOWER,
			Lower: int64(input.Integer),
		}
	case datalog.IntegerComparisonLTE:
		pbIntConstraint = &pb.IntConstraintV1{
			Kind:         pb.IntConstraintV1_LOWER_OR_EQUAL,
			LowerOrEqual: int64(input.Integer),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported int constraint: %v", input.Comparison)
	}
	return pbIntConstraint, nil
}

func tokenIntInConstraintToProtoIntConstraintV1(input datalog.IntegerInChecker) *pb.IntConstraintV1 {
	var pbIntConstraint *pb.IntConstraintV1

	pbSet := make([]int64, 0, len(input.Set))
	for e := range input.Set {
		pbSet = append(pbSet, int64(e))
	}

	if input.Not {
		pbIntConstraint = &pb.IntConstraintV1{
			Kind:     pb.IntConstraintV1_NOT_IN,
			NotInSet: pbSet,
		}
	} else {
		pbIntConstraint = &pb.IntConstraintV1{
			Kind:  pb.IntConstraintV1_IN,
			InSet: pbSet,
		}
	}
	return pbIntConstraint
}

func protoIntConstraintToTokenIntConstraintV1(input *pb.IntConstraintV1) (*datalog.Checker, error) {
	var checker datalog.Checker
	switch input.Kind {
	case pb.IntConstraintV1_EQUAL:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonEqual,
			Integer:    datalog.Integer(input.Equal),
		}
	case pb.IntConstraintV1_IN:
		set := make(map[datalog.Integer]struct{}, len(input.InSet))
		for _, i := range input.InSet {
			set[datalog.Integer(i)] = struct{}{}
		}
		checker = datalog.IntegerInChecker{
			Set: set,
			Not: false,
		}
	case pb.IntConstraintV1_NOT_IN:
		set := make(map[datalog.Integer]struct{}, len(input.NotInSet))
		for _, i := range input.NotInSet {
			set[datalog.Integer(i)] = struct{}{}
		}
		checker = datalog.IntegerInChecker{
			Set: set,
			Not: true,
		}
	case pb.IntConstraintV1_LARGER:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonGT,
			Integer:    datalog.Integer(input.Larger),
		}
	case pb.IntConstraintV1_LARGER_OR_EQUAL:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonGTE,
			Integer:    datalog.Integer(input.LargerOrEqual),
		}
	case pb.IntConstraintV1_LOWER:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonLT,
			Integer:    datalog.Integer(input.Lower),
		}
	case pb.IntConstraintV1_LOWER_OR_EQUAL:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonLTE,
			Integer:    datalog.Integer(input.LowerOrEqual),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported int constraint kind: %v", input.Kind)
	}
	return &checker, nil
}

func tokenStrConstraintToProtoStrConstraintV1(input datalog.StringComparisonChecker) (*pb.StringConstraintV1, error) {
	var pbStrConstraint *pb.StringConstraintV1
	switch input.Comparison {
	case datalog.StringComparisonEqual:
		pbStrConstraint = &pb.StringConstraintV1{
			Kind:  pb.StringConstraintV1_EQUAL,
			Equal: string(input.Str),
		}
	case datalog.StringComparisonPrefix:
		pbStrConstraint = &pb.StringConstraintV1{
			Kind:   pb.StringConstraintV1_PREFIX,
			Prefix: string(input.Str),
		}
	case datalog.StringComparisonSuffix:
		pbStrConstraint = &pb.StringConstraintV1{
			Kind:   pb.StringConstraintV1_SUFFIX,
			Suffix: string(input.Str),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported string constraint: %v", input.Comparison)
	}
	return pbStrConstraint, nil
}

func tokenStrInConstraintToProtoStrConstraintV1(input datalog.StringInChecker) *pb.StringConstraintV1 {
	var pbStringConstraint *pb.StringConstraintV1

	pbSet := make([]string, 0, len(input.Set))
	for e := range input.Set {
		pbSet = append(pbSet, string(e))
	}

	if input.Not {
		pbStringConstraint = &pb.StringConstraintV1{
			Kind:     pb.StringConstraintV1_NOT_IN,
			NotInSet: pbSet,
		}
	} else {
		pbStringConstraint = &pb.StringConstraintV1{
			Kind:  pb.StringConstraintV1_IN,
			InSet: pbSet,
		}
	}
	return pbStringConstraint
}

func protoStrConstraintToTokenStrConstraintV1(input *pb.StringConstraintV1) (*datalog.Checker, error) {
	var checker datalog.Checker
	switch input.Kind {
	case pb.StringConstraintV1_EQUAL:
		checker = datalog.StringComparisonChecker{
			Comparison: datalog.StringComparisonEqual,
			Str:        datalog.String(input.Equal),
		}
	case pb.StringConstraintV1_IN:
		set := make(map[datalog.String]struct{}, len(input.InSet))
		for _, s := range input.InSet {
			set[datalog.String(s)] = struct{}{}
		}
		checker = datalog.StringInChecker{
			Set: set,
			Not: false,
		}
	case pb.StringConstraintV1_NOT_IN:
		set := make(map[datalog.String]struct{}, len(input.NotInSet))
		for _, s := range input.NotInSet {
			set[datalog.String(s)] = struct{}{}
		}
		checker = datalog.StringInChecker{
			Set: set,
			Not: true,
		}
	case pb.StringConstraintV1_PREFIX:
		checker = datalog.StringComparisonChecker{
			Comparison: datalog.StringComparisonPrefix,
			Str:        datalog.String(input.Prefix),
		}
	case pb.StringConstraintV1_REGEX:
		re := datalog.StringRegexpChecker(*regexp.MustCompile(input.Regex))
		checker = &re
	case pb.StringConstraintV1_SUFFIX:
		checker = datalog.StringComparisonChecker{
			Comparison: datalog.StringComparisonSuffix,
			Str:        datalog.String(input.Suffix),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported string constraint kind: %v", input.Kind)
	}

	return &checker, nil
}

func tokenSymbolConstraintToProtoSymbolConstraintV1(input datalog.SymbolInChecker) *pb.SymbolConstraintV1 {
	var pbSymbolConstraint *pb.SymbolConstraintV1

	pbSet := make([]uint64, 0, len(input.Set))
	for e := range input.Set {
		pbSet = append(pbSet, uint64(e))
	}

	if input.Not {
		pbSymbolConstraint = &pb.SymbolConstraintV1{
			Kind:     pb.SymbolConstraintV1_NOT_IN,
			NotInSet: pbSet,
		}
	} else {
		pbSymbolConstraint = &pb.SymbolConstraintV1{
			Kind:  pb.SymbolConstraintV1_IN,
			InSet: pbSet,
		}
	}
	return pbSymbolConstraint
}

func protoSymbolConstraintToTokenSymbolConstraintV1(input *pb.SymbolConstraintV1) (*datalog.Checker, error) {
	var checker datalog.Checker
	switch input.Kind {
	case pb.SymbolConstraintV1_IN:
		set := make(map[datalog.Symbol]struct{}, len(input.InSet))
		for _, s := range input.InSet {
			set[datalog.Symbol(s)] = struct{}{}
		}
		checker = datalog.SymbolInChecker{
			Set: set,
			Not: false,
		}
	case pb.SymbolConstraintV1_NOT_IN:
		set := make(map[datalog.Symbol]struct{}, len(input.NotInSet))
		for _, s := range input.NotInSet {
			set[datalog.Symbol(s)] = struct{}{}
		}
		checker = datalog.SymbolInChecker{
			Set: set,
			Not: true,
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported symbol constraint kind: %v", input.Kind)
	}
	return &checker, nil
}

func tokenBytesConstraintToProtoBytesConstraintV1(input datalog.BytesComparisonChecker) (*pb.BytesConstraintV1, error) {
	var pbBytesConstraint *pb.BytesConstraintV1
	switch input.Comparison {
	case datalog.BytesComparisonEqual:
		pbBytesConstraint = &pb.BytesConstraintV1{
			Kind:  pb.BytesConstraintV1_EQUAL,
			Equal: input.Bytes,
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported bytes comparison: %v", input.Comparison)
	}

	return pbBytesConstraint, nil
}

func tokenBytesInConstraintToProtoBytesConstraintV1(input datalog.BytesInChecker) (*pb.BytesConstraintV1, error) {
	var pbBytesConstraint *pb.BytesConstraintV1
	pbSet := make([][]byte, 0, len(input.Set))
	for e := range input.Set {
		b, err := hex.DecodeString(e)
		if err != nil {
			return nil, fmt.Errorf("biscuit: failed to decode hex string %q: %v", e, err)
		}
		pbSet = append(pbSet, b)
	}

	if input.Not {
		pbBytesConstraint = &pb.BytesConstraintV1{
			Kind:     pb.BytesConstraintV1_NOT_IN,
			NotInSet: pbSet,
		}
	} else {
		pbBytesConstraint = &pb.BytesConstraintV1{
			Kind:  pb.BytesConstraintV1_IN,
			InSet: pbSet,
		}
	}

	return pbBytesConstraint, nil
}

func protoBytesConstraintToTokenBytesConstraintV1(input *pb.BytesConstraintV1) (*datalog.Checker, error) {
	var checker datalog.Checker
	switch input.Kind {
	case pb.BytesConstraintV1_EQUAL:
		checker = datalog.BytesComparisonChecker{
			Comparison: datalog.BytesComparisonEqual,
			Bytes:      input.Equal,
		}
	case pb.BytesConstraintV1_IN:
		set := make(map[string]struct{}, len(input.InSet))
		for _, s := range input.InSet {
			set[hex.EncodeToString(s)] = struct{}{}
		}
		checker = datalog.BytesInChecker{
			Set: set,
			Not: false,
		}
	case pb.BytesConstraintV1_NOT_IN:
		set := make(map[string]struct{}, len(input.NotInSet))
		for _, s := range input.NotInSet {
			set[hex.EncodeToString(s)] = struct{}{}
		}
		checker = datalog.BytesInChecker{
			Set: set,
			Not: true,
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported bytes constraint kind: %v", input.Kind)
	}

	return &checker, nil
}

func tokenCaveatToProtoCaveatV1(input datalog.Caveat) (*pb.CaveatV1, error) {
	pbQueries := make([]*pb.RuleV1, len(input.Queries))
	for i, query := range input.Queries {
		q, err := tokenRuleToProtoRuleV1(query)
		if err != nil {
			return nil, err
		}
		pbQueries[i] = q
	}

	return &pb.CaveatV1{
		Queries: pbQueries,
	}, nil
}

func protoCaveatToTokenCaveatV1(input *pb.CaveatV1) (*datalog.Caveat, error) {
	queries := make([]datalog.Rule, len(input.Queries))
	for i, query := range input.Queries {
		q, err := protoRuleToTokenRuleV1(query)
		if err != nil {
			return nil, err
		}
		queries[i] = *q
	}

	return &datalog.Caveat{
		Queries: queries,
	}, nil
}
