package biscuit

import (
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/flynn/biscuit-go/datalog"
	"github.com/flynn/biscuit-go/pb"
)

func tokenFactToProtoFactV0(input datalog.Fact) (*pb.FactV0, error) {
	pred, err := tokenPredicateToProtoPredicateV0(input.Predicate)
	if err != nil {
		return nil, err
	}

	return &pb.FactV0{
		Predicate: pred,
	}, nil
}

func protoFactToTokenFactV0(input *pb.FactV0) (*datalog.Fact, error) {
	pred, err := protoPredicateToTokenPredicateV0(input.Predicate)
	if err != nil {
		return nil, err
	}
	return &datalog.Fact{
		Predicate: *pred,
	}, nil
}

func tokenPredicateToProtoPredicateV0(input datalog.Predicate) (*pb.PredicateV0, error) {
	pbIds := make([]*pb.IDV0, len(input.IDs))
	var err error
	for i, id := range input.IDs {
		pbIds[i], err = tokenIDToProtoIDV0(id)
		if err != nil {
			return nil, err
		}
	}

	return &pb.PredicateV0{
		Name: uint64(input.Name),
		Ids:  pbIds,
	}, nil
}

func protoPredicateToTokenPredicateV0(input *pb.PredicateV0) (*datalog.Predicate, error) {
	ids := make([]datalog.ID, len(input.Ids))
	for i, id := range input.Ids {
		dlid, err := protoIDToTokenIDV0(id)
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

func tokenIDToProtoIDV0(input datalog.ID) (*pb.IDV0, error) {
	var pbId *pb.IDV0
	switch input.Type() {
	case datalog.IDTypeString:
		pbId = &pb.IDV0{
			Kind: pb.IDV0_STR,
			Str:  string(input.(datalog.String)),
		}
	case datalog.IDTypeDate:
		pbId = &pb.IDV0{
			Kind: pb.IDV0_DATE,
			Date: uint64(input.(datalog.Date)),
		}
	case datalog.IDTypeInteger:
		pbId = &pb.IDV0{
			Kind:    pb.IDV0_INTEGER,
			Integer: int64(input.(datalog.Integer)),
		}
	case datalog.IDTypeSymbol:
		pbId = &pb.IDV0{
			Kind:   pb.IDV0_SYMBOL,
			Symbol: uint64(input.(datalog.Symbol)),
		}
	case datalog.IDTypeVariable:
		pbId = &pb.IDV0{
			Kind:     pb.IDV0_VARIABLE,
			Variable: uint32(input.(datalog.Variable)),
		}
	case datalog.IDTypeBytes:
		pbId = &pb.IDV0{
			Kind:  pb.IDV0_BYTES,
			Bytes: input.(datalog.Bytes),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported id type: %v", input.Type())
	}
	return pbId, nil
}

func protoIDToTokenIDV0(input *pb.IDV0) (*datalog.ID, error) {
	var id datalog.ID
	switch input.Kind {
	case pb.IDV0_STR:
		id = datalog.String(input.Str)
	case pb.IDV0_DATE:
		id = datalog.Date(input.Date)
	case pb.IDV0_INTEGER:
		id = datalog.Integer(input.Integer)
	case pb.IDV0_SYMBOL:
		id = datalog.Symbol(input.Symbol)
	case pb.IDV0_VARIABLE:
		id = datalog.Variable(input.Variable)
	case pb.IDV0_BYTES:
		id = datalog.Bytes(input.Bytes)
	default:
		return nil, fmt.Errorf("biscuit: unsupported id kind: %v", input.Kind)
	}

	return &id, nil
}

func tokenRuleToProtoRuleV0(input datalog.Rule) (*pb.RuleV0, error) {
	pbBody := make([]*pb.PredicateV0, len(input.Body))
	for i, p := range input.Body {
		pred, err := tokenPredicateToProtoPredicateV0(p)
		if err != nil {
			return nil, err
		}
		pbBody[i] = pred
	}

	pbConstraints := make([]*pb.ConstraintV0, len(input.Constraints))
	for i, c := range input.Constraints {
		cons, err := tokenConstraintToProtoConstraintV0(c)
		if err != nil {
			return nil, err
		}
		pbConstraints[i] = cons
	}

	pbHead, err := tokenPredicateToProtoPredicateV0(input.Head)
	if err != nil {
		return nil, err
	}

	return &pb.RuleV0{
		Head:        pbHead,
		Body:        pbBody,
		Constraints: pbConstraints,
	}, nil
}

func protoRuleToTokenRuleV0(input *pb.RuleV0) (*datalog.Rule, error) {
	body := make([]datalog.Predicate, len(input.Body))
	for i, pb := range input.Body {
		b, err := protoPredicateToTokenPredicateV0(pb)
		if err != nil {
			return nil, err
		}
		body[i] = *b
	}

	constraints := make([]datalog.Constraint, len(input.Constraints))
	for i, pbConstraint := range input.Constraints {
		c, err := protoConstraintToTokenConstraintV0(pbConstraint)
		if err != nil {
			return nil, err
		}
		constraints[i] = *c
	}

	head, err := protoPredicateToTokenPredicateV0(input.Head)
	if err != nil {
		return nil, err
	}
	return &datalog.Rule{
		Head:        *head,
		Body:        body,
		Constraints: constraints,
	}, nil
}

func tokenConstraintToProtoConstraintV0(input datalog.Constraint) (*pb.ConstraintV0, error) {
	var pbConstraint *pb.ConstraintV0
	switch input.Checker.(type) {
	case datalog.DateComparisonChecker:
		c, err := tokenDateConstraintToProtoDateConstraintV0(input.Checker.(datalog.DateComparisonChecker))
		if err != nil {
			return nil, err
		}
		pbConstraint = &pb.ConstraintV0{
			Id:   uint32(input.Name),
			Kind: pb.ConstraintV0_DATE,
			Date: c,
		}
	case datalog.IntegerComparisonChecker:
		c, err := tokenIntConstraintToProtoIntConstraintV0(input.Checker.(datalog.IntegerComparisonChecker))
		if err != nil {
			return nil, err
		}
		pbConstraint = &pb.ConstraintV0{
			Id:   uint32(input.Name),
			Kind: pb.ConstraintV0_INT,
			Int:  c,
		}
	case datalog.IntegerInChecker:
		pbConstraint = &pb.ConstraintV0{
			Id:   uint32(input.Name),
			Kind: pb.ConstraintV0_INT,
			Int:  tokenIntInConstraintToProtoIntConstraintV0(input.Checker.(datalog.IntegerInChecker)),
		}
	case datalog.StringComparisonChecker:
		c, err := tokenStrConstraintToProtoStrConstraintV0(input.Checker.(datalog.StringComparisonChecker))
		if err != nil {
			return nil, err
		}
		pbConstraint = &pb.ConstraintV0{
			Id:   uint32(input.Name),
			Kind: pb.ConstraintV0_STRING,
			Str:  c,
		}
	case datalog.StringInChecker:
		pbConstraint = &pb.ConstraintV0{
			Id:   uint32(input.Name),
			Kind: pb.ConstraintV0_STRING,
			Str:  tokenStrInConstraintToProtoStrConstraintV0(input.Checker.(datalog.StringInChecker)),
		}
	case *datalog.StringRegexpChecker:
		pbConstraint = &pb.ConstraintV0{
			Id:   uint32(input.Name),
			Kind: pb.ConstraintV0_STRING,
			Str: &pb.StringConstraintV0{
				Kind:  pb.StringConstraintV0_REGEX,
				Regex: (*regexp.Regexp)(input.Checker.(*datalog.StringRegexpChecker)).String(),
			},
		}
	case datalog.SymbolInChecker:
		pbConstraint = &pb.ConstraintV0{
			Id:     uint32(input.Name),
			Kind:   pb.ConstraintV0_SYMBOL,
			Symbol: tokenSymbolConstraintToProtoSymbolConstraintV0(input.Checker.(datalog.SymbolInChecker)),
		}
	case datalog.BytesComparisonChecker:
		c, err := tokenBytesConstraintToProtoBytesConstraintV0(input.Checker.(datalog.BytesComparisonChecker))
		if err != nil {
			return nil, err
		}
		pbConstraint = &pb.ConstraintV0{
			Id:    uint32(input.Name),
			Kind:  pb.ConstraintV0_BYTES,
			Bytes: c,
		}
	case datalog.BytesInChecker:
		c, err := tokenBytesInConstraintToProtoBytesConstraintV0(input.Checker.(datalog.BytesInChecker))
		if err != nil {
			return nil, err
		}
		pbConstraint = &pb.ConstraintV0{
			Id:    uint32(input.Name),
			Kind:  pb.ConstraintV0_BYTES,
			Bytes: c,
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported constraint type: %v", input.Name.Type())
	}

	return pbConstraint, nil
}

func protoConstraintToTokenConstraintV0(input *pb.ConstraintV0) (*datalog.Constraint, error) {
	var constraint datalog.Constraint
	switch input.Kind {
	case pb.ConstraintV0_DATE:
		c, err := protoDateConstraintToTokenDateConstraintV0(input.Date)
		if err != nil {
			return nil, err
		}
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: *c,
		}
	case pb.ConstraintV0_INT:
		c, err := protoIntConstraintToTokenIntConstraintV0(input.Int)
		if err != nil {
			return nil, err
		}
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: *c,
		}
	case pb.ConstraintV0_STRING:
		c, err := protoStrConstraintToTokenStrConstraintV0(input.Str)
		if err != nil {
			return nil, err
		}
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: *c,
		}
	case pb.ConstraintV0_SYMBOL:
		c, err := protoSymbolConstraintToTokenSymbolConstraintV0(input.Symbol)
		if err != nil {
			return nil, err
		}
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: *c,
		}
	case pb.ConstraintV0_BYTES:
		c, err := protoBytesConstraintToTokenBytesConstraintV0(input.Bytes)
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

func tokenDateConstraintToProtoDateConstraintV0(input datalog.DateComparisonChecker) (*pb.DateConstraintV0, error) {
	var pbDateConstraint *pb.DateConstraintV0
	switch input.Comparison {
	case datalog.DateComparisonBefore:
		pbDateConstraint = &pb.DateConstraintV0{
			Kind:   pb.DateConstraintV0_BEFORE,
			Before: uint64(input.Date),
		}
	case datalog.DateComparisonAfter:
		pbDateConstraint = &pb.DateConstraintV0{
			Kind:  pb.DateConstraintV0_AFTER,
			After: uint64(input.Date),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported date constraint: %v", input.Comparison)
	}

	return pbDateConstraint, nil
}

func protoDateConstraintToTokenDateConstraintV0(input *pb.DateConstraintV0) (*datalog.Checker, error) {
	var checker datalog.Checker
	switch input.Kind {
	case pb.DateConstraintV0_BEFORE:
		checker = datalog.DateComparisonChecker{
			Comparison: datalog.DateComparisonBefore,
			Date:       datalog.Date(input.Before),
		}
	case pb.DateConstraintV0_AFTER:
		checker = datalog.DateComparisonChecker{
			Comparison: datalog.DateComparisonAfter,
			Date:       datalog.Date(input.After),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported date constraint kind: %v", input.Kind)
	}
	return &checker, nil
}

func tokenIntConstraintToProtoIntConstraintV0(input datalog.IntegerComparisonChecker) (*pb.IntConstraintV0, error) {
	var pbIntConstraint *pb.IntConstraintV0
	switch input.Comparison {
	case datalog.IntegerComparisonEqual:
		pbIntConstraint = &pb.IntConstraintV0{
			Kind:  pb.IntConstraintV0_EQUAL,
			Equal: int64(input.Integer),
		}
	case datalog.IntegerComparisonGT:
		pbIntConstraint = &pb.IntConstraintV0{
			Kind:   pb.IntConstraintV0_LARGER,
			Larger: int64(input.Integer),
		}
	case datalog.IntegerComparisonGTE:
		pbIntConstraint = &pb.IntConstraintV0{
			Kind:          pb.IntConstraintV0_LARGER_OR_EQUAL,
			LargerOrEqual: int64(input.Integer),
		}
	case datalog.IntegerComparisonLT:
		pbIntConstraint = &pb.IntConstraintV0{
			Kind:  pb.IntConstraintV0_LOWER,
			Lower: int64(input.Integer),
		}
	case datalog.IntegerComparisonLTE:
		pbIntConstraint = &pb.IntConstraintV0{
			Kind:         pb.IntConstraintV0_LOWER_OR_EQUAL,
			LowerOrEqual: int64(input.Integer),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported int constraint: %v", input.Comparison)
	}
	return pbIntConstraint, nil
}

func tokenIntInConstraintToProtoIntConstraintV0(input datalog.IntegerInChecker) *pb.IntConstraintV0 {
	var pbIntConstraint *pb.IntConstraintV0

	pbSet := make([]int64, 0, len(input.Set))
	for e := range input.Set {
		pbSet = append(pbSet, int64(e))
	}

	if input.Not {
		pbIntConstraint = &pb.IntConstraintV0{
			Kind:     pb.IntConstraintV0_NOT_IN,
			NotInSet: pbSet,
		}
	} else {
		pbIntConstraint = &pb.IntConstraintV0{
			Kind:  pb.IntConstraintV0_IN,
			InSet: pbSet,
		}
	}
	return pbIntConstraint
}

func protoIntConstraintToTokenIntConstraintV0(input *pb.IntConstraintV0) (*datalog.Checker, error) {
	var checker datalog.Checker
	switch input.Kind {
	case pb.IntConstraintV0_EQUAL:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonEqual,
			Integer:    datalog.Integer(input.Equal),
		}
	case pb.IntConstraintV0_IN:
		set := make(map[datalog.Integer]struct{}, len(input.InSet))
		for _, i := range input.InSet {
			set[datalog.Integer(i)] = struct{}{}
		}
		checker = datalog.IntegerInChecker{
			Set: set,
			Not: false,
		}
	case pb.IntConstraintV0_NOT_IN:
		set := make(map[datalog.Integer]struct{}, len(input.NotInSet))
		for _, i := range input.NotInSet {
			set[datalog.Integer(i)] = struct{}{}
		}
		checker = datalog.IntegerInChecker{
			Set: set,
			Not: true,
		}
	case pb.IntConstraintV0_LARGER:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonGT,
			Integer:    datalog.Integer(input.Larger),
		}
	case pb.IntConstraintV0_LARGER_OR_EQUAL:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonGTE,
			Integer:    datalog.Integer(input.LargerOrEqual),
		}
	case pb.IntConstraintV0_LOWER:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonLT,
			Integer:    datalog.Integer(input.Lower),
		}
	case pb.IntConstraintV0_LOWER_OR_EQUAL:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonLTE,
			Integer:    datalog.Integer(input.LowerOrEqual),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported int constraint kind: %v", input.Kind)
	}
	return &checker, nil
}

func tokenStrConstraintToProtoStrConstraintV0(input datalog.StringComparisonChecker) (*pb.StringConstraintV0, error) {
	var pbStrConstraint *pb.StringConstraintV0
	switch input.Comparison {
	case datalog.StringComparisonEqual:
		pbStrConstraint = &pb.StringConstraintV0{
			Kind:  pb.StringConstraintV0_EQUAL,
			Equal: string(input.Str),
		}
	case datalog.StringComparisonPrefix:
		pbStrConstraint = &pb.StringConstraintV0{
			Kind:   pb.StringConstraintV0_PREFIX,
			Prefix: string(input.Str),
		}
	case datalog.StringComparisonSuffix:
		pbStrConstraint = &pb.StringConstraintV0{
			Kind:   pb.StringConstraintV0_SUFFIX,
			Suffix: string(input.Str),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported string constraint: %v", input.Comparison)
	}
	return pbStrConstraint, nil
}

func tokenStrInConstraintToProtoStrConstraintV0(input datalog.StringInChecker) *pb.StringConstraintV0 {
	var pbStringConstraint *pb.StringConstraintV0

	pbSet := make([]string, 0, len(input.Set))
	for e := range input.Set {
		pbSet = append(pbSet, string(e))
	}

	if input.Not {
		pbStringConstraint = &pb.StringConstraintV0{
			Kind:     pb.StringConstraintV0_NOT_IN,
			NotInSet: pbSet,
		}
	} else {
		pbStringConstraint = &pb.StringConstraintV0{
			Kind:  pb.StringConstraintV0_IN,
			InSet: pbSet,
		}
	}
	return pbStringConstraint
}

func protoStrConstraintToTokenStrConstraintV0(input *pb.StringConstraintV0) (*datalog.Checker, error) {
	var checker datalog.Checker
	switch input.Kind {
	case pb.StringConstraintV0_EQUAL:
		checker = datalog.StringComparisonChecker{
			Comparison: datalog.StringComparisonEqual,
			Str:        datalog.String(input.Equal),
		}
	case pb.StringConstraintV0_IN:
		set := make(map[datalog.String]struct{}, len(input.InSet))
		for _, s := range input.InSet {
			set[datalog.String(s)] = struct{}{}
		}
		checker = datalog.StringInChecker{
			Set: set,
			Not: false,
		}
	case pb.StringConstraintV0_NOT_IN:
		set := make(map[datalog.String]struct{}, len(input.NotInSet))
		for _, s := range input.NotInSet {
			set[datalog.String(s)] = struct{}{}
		}
		checker = datalog.StringInChecker{
			Set: set,
			Not: true,
		}
	case pb.StringConstraintV0_PREFIX:
		checker = datalog.StringComparisonChecker{
			Comparison: datalog.StringComparisonPrefix,
			Str:        datalog.String(input.Prefix),
		}
	case pb.StringConstraintV0_REGEX:
		re := datalog.StringRegexpChecker(*regexp.MustCompile(input.Regex))
		checker = &re
	case pb.StringConstraintV0_SUFFIX:
		checker = datalog.StringComparisonChecker{
			Comparison: datalog.StringComparisonSuffix,
			Str:        datalog.String(input.Suffix),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported string constraint kind: %v", input.Kind)
	}

	return &checker, nil
}

func tokenSymbolConstraintToProtoSymbolConstraintV0(input datalog.SymbolInChecker) *pb.SymbolConstraintV0 {
	var pbSymbolConstraint *pb.SymbolConstraintV0

	pbSet := make([]uint64, 0, len(input.Set))
	for e := range input.Set {
		pbSet = append(pbSet, uint64(e))
	}

	if input.Not {
		pbSymbolConstraint = &pb.SymbolConstraintV0{
			Kind:     pb.SymbolConstraintV0_NOT_IN,
			NotInSet: pbSet,
		}
	} else {
		pbSymbolConstraint = &pb.SymbolConstraintV0{
			Kind:  pb.SymbolConstraintV0_IN,
			InSet: pbSet,
		}
	}
	return pbSymbolConstraint
}

func protoSymbolConstraintToTokenSymbolConstraintV0(input *pb.SymbolConstraintV0) (*datalog.Checker, error) {
	var checker datalog.Checker
	switch input.Kind {
	case pb.SymbolConstraintV0_IN:
		set := make(map[datalog.Symbol]struct{}, len(input.InSet))
		for _, s := range input.InSet {
			set[datalog.Symbol(s)] = struct{}{}
		}
		checker = datalog.SymbolInChecker{
			Set: set,
			Not: false,
		}
	case pb.SymbolConstraintV0_NOT_IN:
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

func tokenBytesConstraintToProtoBytesConstraintV0(input datalog.BytesComparisonChecker) (*pb.BytesConstraintV0, error) {
	var pbBytesConstraint *pb.BytesConstraintV0
	switch input.Comparison {
	case datalog.BytesComparisonEqual:
		pbBytesConstraint = &pb.BytesConstraintV0{
			Kind:  pb.BytesConstraintV0_EQUAL,
			Equal: input.Bytes,
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported bytes comparison: %v", input.Comparison)
	}

	return pbBytesConstraint, nil
}

func tokenBytesInConstraintToProtoBytesConstraintV0(input datalog.BytesInChecker) (*pb.BytesConstraintV0, error) {
	var pbBytesConstraint *pb.BytesConstraintV0
	pbSet := make([][]byte, 0, len(input.Set))
	for e := range input.Set {
		b, err := hex.DecodeString(e)
		if err != nil {
			return nil, fmt.Errorf("biscuit: failed to decode hex string %q: %v", e, err)
		}
		pbSet = append(pbSet, b)
	}

	if input.Not {
		pbBytesConstraint = &pb.BytesConstraintV0{
			Kind:     pb.BytesConstraintV0_NOT_IN,
			NotInSet: pbSet,
		}
	} else {
		pbBytesConstraint = &pb.BytesConstraintV0{
			Kind:  pb.BytesConstraintV0_IN,
			InSet: pbSet,
		}
	}

	return pbBytesConstraint, nil
}

func protoBytesConstraintToTokenBytesConstraintV0(input *pb.BytesConstraintV0) (*datalog.Checker, error) {
	var checker datalog.Checker
	switch input.Kind {
	case pb.BytesConstraintV0_EQUAL:
		checker = datalog.BytesComparisonChecker{
			Comparison: datalog.BytesComparisonEqual,
			Bytes:      input.Equal,
		}
	case pb.BytesConstraintV0_IN:
		set := make(map[string]struct{}, len(input.InSet))
		for _, s := range input.InSet {
			set[hex.EncodeToString(s)] = struct{}{}
		}
		checker = datalog.BytesInChecker{
			Set: set,
			Not: false,
		}
	case pb.BytesConstraintV0_NOT_IN:
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

func tokenCaveatToProtoCaveatV0(input datalog.Caveat) (*pb.CaveatV0, error) {
	pbQueries := make([]*pb.RuleV0, len(input.Queries))
	for i, query := range input.Queries {
		q, err := tokenRuleToProtoRuleV0(query)
		if err != nil {
			return nil, err
		}
		pbQueries[i] = q
	}

	return &pb.CaveatV0{
		Queries: pbQueries,
	}, nil
}

func protoCaveatToTokenCaveatV0(input *pb.CaveatV0) (*datalog.Caveat, error) {
	queries := make([]datalog.Rule, len(input.Queries))
	for i, query := range input.Queries {
		q, err := protoRuleToTokenRuleV0(query)
		if err != nil {
			return nil, err
		}
		queries[i] = *q
	}

	return &datalog.Caveat{
		Queries: queries,
	}, nil
}
