package biscuit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
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
			Content: &pb.IDV1_Str{Str: string(input.(datalog.String))},
		}
	case datalog.IDTypeDate:
		pbId = &pb.IDV1{
			Content: &pb.IDV1_Date{Date: uint64(input.(datalog.Date))},
		}
	case datalog.IDTypeInteger:
		pbId = &pb.IDV1{
			Content: &pb.IDV1_Integer{Integer: int64(input.(datalog.Integer))},
		}
	case datalog.IDTypeSymbol:
		pbId = &pb.IDV1{
			Content: &pb.IDV1_Symbol{Symbol: uint64(input.(datalog.Symbol))},
		}
	case datalog.IDTypeVariable:
		pbId = &pb.IDV1{
			Content: &pb.IDV1_Variable{Variable: uint32(input.(datalog.Variable))},
		}
	case datalog.IDTypeBytes:
		pbId = &pb.IDV1{
			Content: &pb.IDV1_Bytes{Bytes: input.(datalog.Bytes)},
		}
	case datalog.IDTypeBool:
		pbId = &pb.IDV1{
			Content: &pb.IDV1_Bool{Bool: bool(input.(datalog.Bool))},
		}
	case datalog.IDTypeSet:
		datalogSet := input.(datalog.Set)
		if len(datalogSet) == 0 {
			return nil, errors.New("biscuit: failed to convert token ID to proto ID: set cannot be empty")
		}

		expectedEltType := datalogSet[0].Type()
		switch expectedEltType {
		case datalog.IDTypeVariable:
			return nil, errors.New("biscuit: failed to convert token ID to proto ID: set cannot contain variable")
		case datalog.IDTypeSet:
			return nil, errors.New("biscuit: failed to convert token ID to proto ID: set cannot contain other sets")
		}

		protoSet := make([]*pb.IDV1, 0, len(datalogSet))
		for _, datalogElt := range datalogSet {
			if datalogElt.Type() != expectedEltType {
				return nil, fmt.Errorf(
					"biscuit: failed to convert token ID to proto ID: set elements must have the same type (got %x, want %x)",
					datalogElt.Type(),
					expectedEltType,
				)
			}

			protoElt, err := tokenIDToProtoIDV1(datalogElt)
			if err != nil {
				return nil, err
			}

			protoSet = append(protoSet, protoElt)
		}
		pbId = &pb.IDV1{
			Content: &pb.IDV1_Set{
				Set: &pb.IDSet{
					Set: protoSet,
				},
			},
		}
	default:
		return nil, fmt.Errorf("biscuit: failed to convert token ID to proto ID: unsupported id type: %v", input.Type())
	}
	return pbId, nil
}

func protoIDToTokenIDV1(input *pb.IDV1) (*datalog.ID, error) {
	var id datalog.ID
	switch input.Content.(type) {
	case *pb.IDV1_Str:
		id = datalog.String(input.GetStr())
	case *pb.IDV1_Date:
		id = datalog.Date(input.GetDate())
	case *pb.IDV1_Integer:
		id = datalog.Integer(input.GetInteger())
	case *pb.IDV1_Symbol:
		id = datalog.Symbol(input.GetSymbol())
	case *pb.IDV1_Variable:
		id = datalog.Variable(input.GetVariable())
	case *pb.IDV1_Bytes:
		id = datalog.Bytes(input.GetBytes())
	case *pb.IDV1_Bool:
		id = datalog.Bool(input.GetBool())
	case *pb.IDV1_Set:
		elts := input.GetSet().Set
		if len(elts) == 0 {
			return nil, errors.New("biscuit: failed to convert proto ID to token ID: set cannot be empty")
		}

		expectedEltType := reflect.TypeOf(elts[0].GetContent())
		switch expectedEltType {
		case reflect.TypeOf(&pb.IDV1_Variable{}):
			return nil, errors.New("biscuit: failed to convert proto ID to token ID: set cannot contain variable")
		case reflect.TypeOf(&pb.IDV1_Set{}):
			return nil, errors.New("biscuit: failed to convert proto ID to token ID: set cannot contain other sets")
		}

		datalogSet := make(datalog.Set, 0, len(elts))
		for _, protoElt := range elts {
			if eltType := reflect.TypeOf(protoElt.GetContent()); eltType != expectedEltType {
				return nil, fmt.Errorf(
					"biscuit: failed to convert proto ID to token ID: set elements must have the same type (got %x, want %x)",
					eltType,
					expectedEltType,
				)
			}

			datalogElt, err := protoIDToTokenIDV1(protoElt)
			if err != nil {
				return nil, err
			}
			datalogSet = append(datalogSet, *datalogElt)
		}
		id = datalogSet
	default:
		return nil, fmt.Errorf("biscuit: failed to convert proto ID to token ID: unsupported id type: %T", input.Content)
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
			Id:         uint32(input.Name),
			Constraint: &pb.ConstraintV1_Date{Date: c},
		}
	case datalog.IntegerComparisonChecker:
		c, err := tokenIntConstraintToProtoIntConstraintV1(input.Checker.(datalog.IntegerComparisonChecker))
		if err != nil {
			return nil, err
		}
		pbConstraint = &pb.ConstraintV1{
			Id:         uint32(input.Name),
			Constraint: &pb.ConstraintV1_Int{Int: c},
		}
	case datalog.IntegerInChecker:
		pbConstraint = &pb.ConstraintV1{
			Id: uint32(input.Name),
			Constraint: &pb.ConstraintV1_Int{
				Int: tokenIntInConstraintToProtoIntConstraintV1(input.Checker.(datalog.IntegerInChecker)),
			},
		}
	case datalog.StringComparisonChecker:
		c, err := tokenStrConstraintToProtoStrConstraintV1(input.Checker.(datalog.StringComparisonChecker))
		if err != nil {
			return nil, err
		}
		pbConstraint = &pb.ConstraintV1{
			Id:         uint32(input.Name),
			Constraint: &pb.ConstraintV1_Str{Str: c},
		}
	case datalog.StringInChecker:
		pbConstraint = &pb.ConstraintV1{
			Id: uint32(input.Name),
			Constraint: &pb.ConstraintV1_Str{
				Str: tokenStrInConstraintToProtoStrConstraintV1(input.Checker.(datalog.StringInChecker)),
			},
		}
	case *datalog.StringRegexpChecker:
		pbConstraint = &pb.ConstraintV1{
			Id: uint32(input.Name),
			Constraint: &pb.ConstraintV1_Str{
				Str: &pb.StringConstraintV1{
					Constraint: &pb.StringConstraintV1_Regex{
						Regex: (*regexp.Regexp)(input.Checker.(*datalog.StringRegexpChecker)).String(),
					},
				},
			},
		}
	case datalog.SymbolInChecker:
		pbConstraint = &pb.ConstraintV1{
			Id: uint32(input.Name),
			Constraint: &pb.ConstraintV1_Symbol{
				Symbol: tokenSymbolConstraintToProtoSymbolConstraintV1(input.Checker.(datalog.SymbolInChecker)),
			},
		}
	case datalog.BytesComparisonChecker:
		c, err := tokenBytesConstraintToProtoBytesConstraintV1(input.Checker.(datalog.BytesComparisonChecker))
		if err != nil {
			return nil, err
		}
		pbConstraint = &pb.ConstraintV1{
			Id:         uint32(input.Name),
			Constraint: &pb.ConstraintV1_Bytes{Bytes: c},
		}
	case datalog.BytesInChecker:
		c, err := tokenBytesInConstraintToProtoBytesConstraintV1(input.Checker.(datalog.BytesInChecker))
		if err != nil {
			return nil, err
		}
		pbConstraint = &pb.ConstraintV1{
			Id:         uint32(input.Name),
			Constraint: &pb.ConstraintV1_Bytes{Bytes: c},
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported constraint type: %v", input.Name.Type())
	}

	return pbConstraint, nil
}

func protoConstraintToTokenConstraintV1(input *pb.ConstraintV1) (*datalog.Constraint, error) {
	var constraint datalog.Constraint
	switch input.Constraint.(type) {
	case *pb.ConstraintV1_Date:
		c, err := protoDateConstraintToTokenDateConstraintV1(input.GetDate())
		if err != nil {
			return nil, err
		}
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: *c,
		}
	case *pb.ConstraintV1_Int:
		c, err := protoIntConstraintToTokenIntConstraintV1(input.GetInt())
		if err != nil {
			return nil, err
		}
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: *c,
		}
	case *pb.ConstraintV1_Str:
		c, err := protoStrConstraintToTokenStrConstraintV1(input.GetStr())
		if err != nil {
			return nil, err
		}
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: *c,
		}
	case *pb.ConstraintV1_Symbol:
		c, err := protoSymbolConstraintToTokenSymbolConstraintV1(input.GetSymbol())
		if err != nil {
			return nil, err
		}
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: *c,
		}
	case *pb.ConstraintV1_Bytes:
		c, err := protoBytesConstraintToTokenBytesConstraintV1(input.GetBytes())
		if err != nil {
			return nil, err
		}
		constraint = datalog.Constraint{
			Name:    datalog.Variable(input.Id),
			Checker: *c,
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported constraint type: %T", input.Constraint)
	}

	return &constraint, nil
}

func tokenDateConstraintToProtoDateConstraintV1(input datalog.DateComparisonChecker) (*pb.DateConstraintV1, error) {
	var pbDateConstraint *pb.DateConstraintV1
	switch input.Comparison {
	case datalog.DateComparisonBefore:
		pbDateConstraint = &pb.DateConstraintV1{
			Constraint: &pb.DateConstraintV1_Before{Before: uint64(input.Date)},
		}
	case datalog.DateComparisonAfter:
		pbDateConstraint = &pb.DateConstraintV1{
			Constraint: &pb.DateConstraintV1_After{After: uint64(input.Date)},
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported date constraint: %v", input.Comparison)
	}

	return pbDateConstraint, nil
}

func protoDateConstraintToTokenDateConstraintV1(input *pb.DateConstraintV1) (*datalog.Checker, error) {
	var checker datalog.Checker
	switch input.Constraint.(type) {
	case *pb.DateConstraintV1_Before:
		checker = datalog.DateComparisonChecker{
			Comparison: datalog.DateComparisonBefore,
			Date:       datalog.Date(input.GetBefore()),
		}
	case *pb.DateConstraintV1_After:
		checker = datalog.DateComparisonChecker{
			Comparison: datalog.DateComparisonAfter,
			Date:       datalog.Date(input.GetAfter()),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported date constraint type: %T", input.Constraint)
	}
	return &checker, nil
}

func tokenIntConstraintToProtoIntConstraintV1(input datalog.IntegerComparisonChecker) (*pb.IntConstraintV1, error) {
	var pbIntConstraint *pb.IntConstraintV1
	switch input.Comparison {
	case datalog.IntegerComparisonEqual:
		pbIntConstraint = &pb.IntConstraintV1{
			Constraint: &pb.IntConstraintV1_Equal{Equal: int64(input.Integer)},
		}
	case datalog.IntegerComparisonGT:
		pbIntConstraint = &pb.IntConstraintV1{
			Constraint: &pb.IntConstraintV1_GreaterThan{GreaterThan: int64(input.Integer)},
		}
	case datalog.IntegerComparisonGTE:
		pbIntConstraint = &pb.IntConstraintV1{
			Constraint: &pb.IntConstraintV1_GreaterOrEqual{GreaterOrEqual: int64(input.Integer)},
		}
	case datalog.IntegerComparisonLT:
		pbIntConstraint = &pb.IntConstraintV1{
			Constraint: &pb.IntConstraintV1_LessThan{LessThan: int64(input.Integer)},
		}
	case datalog.IntegerComparisonLTE:
		pbIntConstraint = &pb.IntConstraintV1{
			Constraint: &pb.IntConstraintV1_LessOrEqual{LessOrEqual: int64(input.Integer)},
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
			Constraint: &pb.IntConstraintV1_NotInSet{NotInSet: &pb.IntSet{Set: pbSet}},
		}
	} else {
		pbIntConstraint = &pb.IntConstraintV1{
			Constraint: &pb.IntConstraintV1_InSet{InSet: &pb.IntSet{Set: pbSet}},
		}
	}
	return pbIntConstraint
}

func protoIntConstraintToTokenIntConstraintV1(input *pb.IntConstraintV1) (*datalog.Checker, error) {
	var checker datalog.Checker
	switch input.Constraint.(type) {
	case *pb.IntConstraintV1_Equal:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonEqual,
			Integer:    datalog.Integer(input.GetEqual()),
		}
	case *pb.IntConstraintV1_InSet:
		set := make(map[datalog.Integer]struct{}, len(input.GetInSet().GetSet()))
		for _, i := range input.GetInSet().GetSet() {
			set[datalog.Integer(i)] = struct{}{}
		}
		checker = datalog.IntegerInChecker{
			Set: set,
			Not: false,
		}
	case *pb.IntConstraintV1_NotInSet:
		set := make(map[datalog.Integer]struct{}, len(input.GetNotInSet().GetSet()))
		for _, i := range input.GetNotInSet().GetSet() {
			set[datalog.Integer(i)] = struct{}{}
		}
		checker = datalog.IntegerInChecker{
			Set: set,
			Not: true,
		}
	case *pb.IntConstraintV1_GreaterThan:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonGT,
			Integer:    datalog.Integer(input.GetGreaterThan()),
		}
	case *pb.IntConstraintV1_GreaterOrEqual:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonGTE,
			Integer:    datalog.Integer(input.GetGreaterOrEqual()),
		}
	case *pb.IntConstraintV1_LessThan:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonLT,
			Integer:    datalog.Integer(input.GetLessThan()),
		}
	case *pb.IntConstraintV1_LessOrEqual:
		checker = datalog.IntegerComparisonChecker{
			Comparison: datalog.IntegerComparisonLTE,
			Integer:    datalog.Integer(input.GetLessOrEqual()),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported int constraint type: %T", input.Constraint)
	}
	return &checker, nil
}

func tokenStrConstraintToProtoStrConstraintV1(input datalog.StringComparisonChecker) (*pb.StringConstraintV1, error) {
	var pbStrConstraint *pb.StringConstraintV1
	switch input.Comparison {
	case datalog.StringComparisonEqual:
		pbStrConstraint = &pb.StringConstraintV1{
			Constraint: &pb.StringConstraintV1_Equal{Equal: string(input.Str)},
		}
	case datalog.StringComparisonPrefix:
		pbStrConstraint = &pb.StringConstraintV1{
			Constraint: &pb.StringConstraintV1_Prefix{Prefix: string(input.Str)},
		}
	case datalog.StringComparisonSuffix:
		pbStrConstraint = &pb.StringConstraintV1{
			Constraint: &pb.StringConstraintV1_Suffix{Suffix: string(input.Str)},
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
			Constraint: &pb.StringConstraintV1_NotInSet{NotInSet: &pb.StringSet{Set: pbSet}},
		}
	} else {
		pbStringConstraint = &pb.StringConstraintV1{
			Constraint: &pb.StringConstraintV1_InSet{InSet: &pb.StringSet{Set: pbSet}},
		}
	}
	return pbStringConstraint
}

func protoStrConstraintToTokenStrConstraintV1(input *pb.StringConstraintV1) (*datalog.Checker, error) {
	var checker datalog.Checker
	switch input.Constraint.(type) {
	case *pb.StringConstraintV1_Equal:
		checker = datalog.StringComparisonChecker{
			Comparison: datalog.StringComparisonEqual,
			Str:        datalog.String(input.GetEqual()),
		}
	case *pb.StringConstraintV1_InSet:
		set := make(map[datalog.String]struct{}, len(input.GetInSet().GetSet()))
		for _, s := range input.GetInSet().GetSet() {
			set[datalog.String(s)] = struct{}{}
		}
		checker = datalog.StringInChecker{
			Set: set,
			Not: false,
		}
	case *pb.StringConstraintV1_NotInSet:
		set := make(map[datalog.String]struct{}, len(input.GetNotInSet().GetSet()))
		for _, s := range input.GetNotInSet().GetSet() {
			set[datalog.String(s)] = struct{}{}
		}
		checker = datalog.StringInChecker{
			Set: set,
			Not: true,
		}
	case *pb.StringConstraintV1_Prefix:
		checker = datalog.StringComparisonChecker{
			Comparison: datalog.StringComparisonPrefix,
			Str:        datalog.String(input.GetPrefix()),
		}
	case *pb.StringConstraintV1_Regex:
		re := datalog.StringRegexpChecker(*regexp.MustCompile(input.GetRegex()))
		checker = &re
	case *pb.StringConstraintV1_Suffix:
		checker = datalog.StringComparisonChecker{
			Comparison: datalog.StringComparisonSuffix,
			Str:        datalog.String(input.GetSuffix()),
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported string constraint type: %T", input.Constraint)
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
			Constraint: &pb.SymbolConstraintV1_NotInSet{NotInSet: &pb.SymbolSet{Set: pbSet}},
		}
	} else {
		pbSymbolConstraint = &pb.SymbolConstraintV1{
			Constraint: &pb.SymbolConstraintV1_InSet{InSet: &pb.SymbolSet{Set: pbSet}},
		}
	}
	return pbSymbolConstraint
}

func protoSymbolConstraintToTokenSymbolConstraintV1(input *pb.SymbolConstraintV1) (*datalog.Checker, error) {
	var checker datalog.Checker
	switch input.Constraint.(type) {
	case *pb.SymbolConstraintV1_InSet:
		set := make(map[datalog.Symbol]struct{}, len(input.GetInSet().GetSet()))
		for _, s := range input.GetInSet().GetSet() {
			set[datalog.Symbol(s)] = struct{}{}
		}
		checker = datalog.SymbolInChecker{
			Set: set,
			Not: false,
		}
	case *pb.SymbolConstraintV1_NotInSet:
		set := make(map[datalog.Symbol]struct{}, len(input.GetNotInSet().GetSet()))
		for _, s := range input.GetNotInSet().GetSet() {
			set[datalog.Symbol(s)] = struct{}{}
		}
		checker = datalog.SymbolInChecker{
			Set: set,
			Not: true,
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported symbol constraint type: %T", input.Constraint)
	}
	return &checker, nil
}

func tokenBytesConstraintToProtoBytesConstraintV1(input datalog.BytesComparisonChecker) (*pb.BytesConstraintV1, error) {
	var pbBytesConstraint *pb.BytesConstraintV1
	switch input.Comparison {
	case datalog.BytesComparisonEqual:
		pbBytesConstraint = &pb.BytesConstraintV1{
			Constraint: &pb.BytesConstraintV1_Equal{Equal: input.Bytes},
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
			Constraint: &pb.BytesConstraintV1_NotInSet{NotInSet: &pb.BytesSet{Set: pbSet}},
		}
	} else {
		pbBytesConstraint = &pb.BytesConstraintV1{
			Constraint: &pb.BytesConstraintV1_InSet{InSet: &pb.BytesSet{Set: pbSet}},
		}
	}

	return pbBytesConstraint, nil
}

func protoBytesConstraintToTokenBytesConstraintV1(input *pb.BytesConstraintV1) (*datalog.Checker, error) {
	var checker datalog.Checker
	switch input.Constraint.(type) {
	case *pb.BytesConstraintV1_Equal:
		checker = datalog.BytesComparisonChecker{
			Comparison: datalog.BytesComparisonEqual,
			Bytes:      input.GetEqual(),
		}
	case *pb.BytesConstraintV1_InSet:
		set := make(map[string]struct{}, len(input.GetInSet().GetSet()))
		for _, s := range input.GetInSet().GetSet() {
			set[hex.EncodeToString(s)] = struct{}{}
		}
		checker = datalog.BytesInChecker{
			Set: set,
			Not: false,
		}
	case *pb.BytesConstraintV1_NotInSet:
		set := make(map[string]struct{}, len(input.GetNotInSet().GetSet()))
		for _, s := range input.GetNotInSet().GetSet() {
			set[hex.EncodeToString(s)] = struct{}{}
		}
		checker = datalog.BytesInChecker{
			Set: set,
			Not: true,
		}
	default:
		return nil, fmt.Errorf("biscuit: unsupported bytes constraint type: %T", input.Constraint)
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
