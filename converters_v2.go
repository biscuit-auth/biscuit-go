// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
)

func tokenFactToProtoFactV2(input datalog.Fact) (*pb.Fact, error) {
	pred, err := tokenPredicateToProtoPredicateV2(input.Predicate)
	if err != nil {
		return nil, err
	}

	return &pb.Fact{
		Predicate: pred,
	}, nil
}

func protoFactToTokenFactV2(input *pb.Fact) (*datalog.Fact, error) {
	pred, err := protoPredicateToTokenPredicateV2(input.Predicate)
	if err != nil {
		return nil, err
	}
	return &datalog.Fact{
		Predicate: *pred,
	}, nil
}

func tokenPredicateToProtoPredicateV2(input datalog.Predicate) (*pb.Predicate, error) {
	pbTerms := make([]*pb.Term, len(input.Terms))
	var err error
	for i, id := range input.Terms {
		pbTerms[i], err = tokenIDToProtoIDV2(id)
		if err != nil {
			return nil, err
		}
	}

	nameSymbol := uint64(input.Name)
	return &pb.Predicate{
		Name:  &nameSymbol,
		Terms: pbTerms,
	}, nil
}

func protoPredicateToTokenPredicateV2(input *pb.Predicate) (*datalog.Predicate, error) {
	Terms := make([]datalog.Term, len(input.Terms))
	for i, id := range input.Terms {
		dlid, err := protoIDToTokenIDV2(id)
		if err != nil {
			return nil, err
		}

		Terms[i] = *dlid
	}

	nameSymbol := datalog.String(*input.Name)
	return &datalog.Predicate{
		Name:  nameSymbol,
		Terms: Terms,
	}, nil
}

func tokenIDToProtoIDV2(input datalog.Term) (*pb.Term, error) {
	var pbId *pb.Term
	switch input.Type() {
	case datalog.TermTypeString:
		pbId = &pb.Term{
			Content: &pb.Term_String_{String_: uint64(input.(datalog.String))},
		}
	case datalog.TermTypeDate:
		pbId = &pb.Term{
			Content: &pb.Term_Date{Date: uint64(input.(datalog.Date))},
		}
	case datalog.TermTypeInteger:
		pbId = &pb.Term{
			Content: &pb.Term_Integer{Integer: int64(input.(datalog.Integer))},
		}
	case datalog.TermTypeVariable:
		pbId = &pb.Term{
			Content: &pb.Term_Variable{Variable: uint32(input.(datalog.Variable))},
		}
	case datalog.TermTypeBytes:
		pbId = &pb.Term{
			Content: &pb.Term_Bytes{Bytes: input.(datalog.Bytes)},
		}
	case datalog.TermTypeBool:
		pbId = &pb.Term{
			Content: &pb.Term_Bool{Bool: bool(input.(datalog.Bool))},
		}
	case datalog.TermTypeNull:
		pbId = &pb.Term{
			Content: &pb.Term_Null{Null: &pb.Empty{}},
		}
	case datalog.TermTypeArray:
		array := input.(datalog.Array)
		protoArray := make([]*pb.Term, len(array))
		for i, elt := range array {
			if elt.Type() == datalog.TermTypeVariable {
				return nil, errors.New("biscuit: failed to convert token ID to proto ID: array cannot contain variables")
			}
			protoElt, err := tokenIDToProtoIDV2(elt)
			if err != nil {
				return nil, err
			}
			protoArray[i] = protoElt
		}
		pbId = &pb.Term{
			Content: &pb.Term_Array{Array: &pb.Array{Array: protoArray}},
		}
	case datalog.TermTypeMap:
		m := input.(datalog.Map)
		entries := make([]*pb.MapEntry, len(m))
		for i, e := range m {
			key := &pb.MapKey{}
			switch k := e.Key.(type) {
			case datalog.Integer:
				key.Content = &pb.MapKey_Integer{Integer: int64(k)}
			case datalog.String:
				key.Content = &pb.MapKey_String_{String_: uint64(k)}
			default:
				return nil, fmt.Errorf("biscuit: failed to convert token ID to proto ID: map key must be an integer or a string, got %T", e.Key)
			}
			if e.Value.Type() == datalog.TermTypeVariable {
				return nil, errors.New("biscuit: failed to convert token ID to proto ID: map cannot contain variables")
			}
			value, err := tokenIDToProtoIDV2(e.Value)
			if err != nil {
				return nil, err
			}
			entries[i] = &pb.MapEntry{Key: key, Value: value}
		}
		pbId = &pb.Term{
			Content: &pb.Term_Map{Map: &pb.Map{Entries: entries}},
		}
	case datalog.TermTypeSet:
		datalogSet := input.(datalog.Set)
		protoSet := make([]*pb.Term, 0, len(datalogSet))
		for i, datalogElt := range datalogSet {
			switch datalogElt.Type() {
			case datalog.TermTypeVariable:
				return nil, errors.New("biscuit: failed to convert token ID to proto ID: set cannot contains variable")
			case datalog.TermTypeSet:
				return nil, errors.New("biscuit: failed to convert token ID to proto ID: set cannot contains other sets")
			}
			if expectedEltType := datalogSet[0].Type(); i > 0 && datalogElt.Type() != expectedEltType {
				return nil, fmt.Errorf(
					"biscuit: failed to convert token ID to proto ID: set elements must have the same type (got %x, want %x)",
					datalogElt.Type(),
					expectedEltType,
				)
			}

			protoElt, err := tokenIDToProtoIDV2(datalogElt)
			if err != nil {
				return nil, err
			}

			protoSet = append(protoSet, protoElt)
		}
		pbId = &pb.Term{
			Content: &pb.Term_Set{
				Set: &pb.TermSet{
					Set: protoSet,
				},
			},
		}
	default:
		return nil, fmt.Errorf("biscuit: failed to convert token ID to proto ID: unsupported id type: %v", input.Type())
	}
	return pbId, nil
}

func protoIDToTokenIDV2(input *pb.Term) (*datalog.Term, error) {
	var id datalog.Term
	switch input.Content.(type) {
	case *pb.Term_String_:
		id = datalog.String(input.GetString_())
	case *pb.Term_Date:
		id = datalog.Date(input.GetDate())
	case *pb.Term_Integer:
		id = datalog.Integer(input.GetInteger())
	case *pb.Term_Variable:
		id = datalog.Variable(input.GetVariable())
	case *pb.Term_Bytes:
		id = datalog.Bytes(input.GetBytes())
	case *pb.Term_Bool:
		id = datalog.Bool(input.GetBool())
	case *pb.Term_Null:
		id = datalog.Null{}
	case *pb.Term_Set:
		elts := input.GetSet().Set
		datalogSet := make(datalog.Set, 0, len(elts))
		for i, protoElt := range elts {
			switch protoElt.GetContent().(type) {
			case *pb.Term_Variable:
				return nil, errors.New("biscuit: failed to convert proto ID to token ID: set cannot contains variable")
			case *pb.Term_Set:
				return nil, errors.New("biscuit: failed to convert proto ID to token ID: set cannot contains other sets")
			}
			if eltType, expectedEltType := reflect.TypeOf(protoElt.GetContent()), reflect.TypeOf(elts[0].GetContent()); i > 0 && eltType != expectedEltType {
				return nil, fmt.Errorf(
					"biscuit: failed to convert proto ID to token ID: set elements must have the same type (got %x, want %x)",
					eltType,
					expectedEltType,
				)
			}

			datalogElt, err := protoIDToTokenIDV2(protoElt)
			if err != nil {
				return nil, err
			}
			datalogSet = append(datalogSet, *datalogElt)
		}
		id = datalogSet
	case *pb.Term_Array:
		elts := input.GetArray().GetArray()
		array := make(datalog.Array, len(elts))
		for i, protoElt := range elts {
			if _, isVar := protoElt.GetContent().(*pb.Term_Variable); isVar {
				return nil, errors.New("biscuit: failed to convert proto ID to token ID: array cannot contain variables")
			}
			elt, err := protoIDToTokenIDV2(protoElt)
			if err != nil {
				return nil, err
			}
			array[i] = *elt
		}
		id = array
	case *pb.Term_Map:
		pbEntries := input.GetMap().GetEntries()
		entries := make([]datalog.MapEntry, len(pbEntries))
		for i, e := range pbEntries {
			var key datalog.Term
			switch k := e.GetKey().GetContent().(type) {
			case *pb.MapKey_Integer:
				key = datalog.Integer(k.Integer)
			case *pb.MapKey_String_:
				key = datalog.String(k.String_)
			default:
				return nil, fmt.Errorf("biscuit: failed to convert proto ID to token ID: unsupported map key: %T", e.GetKey().GetContent())
			}
			if _, isVar := e.GetValue().GetContent().(*pb.Term_Variable); isVar {
				return nil, errors.New("biscuit: failed to convert proto ID to token ID: map cannot contain variables")
			}
			value, err := protoIDToTokenIDV2(e.GetValue())
			if err != nil {
				return nil, err
			}
			entries[i] = datalog.MapEntry{Key: key, Value: *value}
		}
		id = datalog.NewMap(entries...)
	default:
		return nil, fmt.Errorf("biscuit: failed to convert proto ID to token ID: unsupported id type: %T", input.Content)
	}

	return &id, nil
}

func tokenRuleToProtoRuleV2(input datalog.Rule, keys publicKeyTable) (*pb.Rule, error) {
	pbBody := make([]*pb.Predicate, len(input.Body))
	for i, p := range input.Body {
		pred, err := tokenPredicateToProtoPredicateV2(p)
		if err != nil {
			return nil, err
		}
		pbBody[i] = pred
	}

	pbExpressions := make([]*pb.Expression, len(input.Expressions))
	for i, e := range input.Expressions {
		expr, err := tokenExpressionToProtoExpressionV2(e)
		if err != nil {
			return nil, err
		}
		pbExpressions[i] = expr
	}

	pbHead, err := tokenPredicateToProtoPredicateV2(input.Head)
	if err != nil {
		return nil, err
	}

	pbScopes, err := tokenScopesToProtoScopes(input.Scopes, keys)
	if err != nil {
		return nil, err
	}

	return &pb.Rule{
		Head:        pbHead,
		Body:        pbBody,
		Expressions: pbExpressions,
		Scope:       pbScopes,
	}, nil
}

func protoRuleToTokenRuleV2(input *pb.Rule, keys publicKeyTable) (*datalog.Rule, error) {
	body := make([]datalog.Predicate, len(input.Body))
	for i, predicateV2 := range input.Body {
		b, err := protoPredicateToTokenPredicateV2(predicateV2)
		if err != nil {
			return nil, err
		}
		body[i] = *b
	}

	expressions := make([]datalog.Expression, len(input.Expressions))
	for i, pbExpression := range input.Expressions {
		e, err := protoExpressionToTokenExpressionV2(pbExpression)
		if err != nil {
			return nil, err
		}
		expressions[i] = e
	}

	head, err := protoPredicateToTokenPredicateV2(input.Head)
	if err != nil {
		return nil, err
	}

	scopes, err := protoScopesToTokenScopes(input.Scope, keys)
	if err != nil {
		return nil, err
	}

	return &datalog.Rule{
		Head:        *head,
		Body:        body,
		Expressions: expressions,
		Scopes:      scopes,
	}, nil
}

func tokenExpressionToProtoExpressionV2(input datalog.Expression) (*pb.Expression, error) {
	pbExpr := &pb.Expression{
		Ops: make([]*pb.Op, len(input)),
	}

	for i, op := range input {
		switch op.Type() {
		case datalog.OpTypeValue:
			pbID, err := tokenIDToProtoIDV2(op.(datalog.Value).ID)
			if err != nil {
				return nil, err
			}
			pbExpr.Ops[i] = &pb.Op{Content: &pb.Op_Value{Value: pbID}}
		case datalog.OpTypeUnary:
			pbUnary, err := tokenExprUnaryToProtoExprUnary(op.(datalog.UnaryOp))
			if err != nil {
				return nil, err
			}
			pbExpr.Ops[i] = &pb.Op{Content: &pb.Op_Unary{Unary: pbUnary}}
		case datalog.OpTypeBinary:
			pbBinary, err := tokenExprBinaryToProtoExprBinary(op.(datalog.BinaryOp))
			if err != nil {
				return nil, err
			}
			pbExpr.Ops[i] = &pb.Op{Content: &pb.Op_Binary{Binary: pbBinary}}
		case datalog.OpTypeClosure:
			closure := op.(datalog.Closure)
			body, err := tokenExpressionToProtoExpressionV2(closure.Body)
			if err != nil {
				return nil, err
			}
			params := make([]uint32, len(closure.Params))
			for j, p := range closure.Params {
				params[j] = uint32(p)
			}
			pbExpr.Ops[i] = &pb.Op{Content: &pb.Op_Closure{Closure: &pb.OpClosure{Params: params, Ops: body.Ops}}}
		default:
			return nil, fmt.Errorf("biscuit: unsupported expression type: %v", op.Type())
		}
	}
	return pbExpr, nil
}

func protoExpressionToTokenExpressionV2(input *pb.Expression) (datalog.Expression, error) {
	expr := make(datalog.Expression, len(input.Ops))
	for i, op := range input.Ops {
		switch op.Content.(type) {
		case *pb.Op_Value:
			id, err := protoIDToTokenIDV2(op.GetValue())
			if err != nil {
				return nil, err
			}
			expr[i] = datalog.Value{ID: *id}
		case *pb.Op_Unary:
			op, err := protoExprUnaryToTokenExprUnary(op.GetUnary())
			if err != nil {
				return nil, err
			}
			expr[i] = datalog.UnaryOp{UnaryOpFunc: op}
		case *pb.Op_Binary:
			op, err := protoExprBinaryToTokenExprBinary(op.GetBinary())
			if err != nil {
				return nil, err
			}
			expr[i] = datalog.BinaryOp{BinaryOpFunc: op}
		case *pb.Op_Closure:
			closure := op.GetClosure()
			body, err := protoExpressionToTokenExpressionV2(&pb.Expression{Ops: closure.GetOps()})
			if err != nil {
				return nil, err
			}
			params := make([]datalog.Variable, len(closure.GetParams()))
			for j, p := range closure.GetParams() {
				params[j] = datalog.Variable(p)
			}
			expr[i] = datalog.Closure{Params: params, Body: body}
		default:
			return nil, fmt.Errorf("biscuit: unsupported proto expression type: %T", op.Content)
		}
	}
	return expr, nil
}

func tokenExprUnaryToProtoExprUnary(op datalog.UnaryOp) (*pb.OpUnary, error) {
	var pbUnaryKind pb.OpUnary_Kind
	switch op.UnaryOpFunc.Type() {
	case datalog.UnaryNegate:
		pbUnaryKind = pb.OpUnary_Negate
	case datalog.UnaryParens:
		pbUnaryKind = pb.OpUnary_Parens
	case datalog.UnaryLength:
		pbUnaryKind = pb.OpUnary_Length
	case datalog.UnaryTypeOf:
		pbUnaryKind = pb.OpUnary_TypeOf
	case datalog.UnaryFfi:
		pbUnaryKind = pb.OpUnary_Ffi
		name := uint64(op.UnaryOpFunc.(datalog.Ffi).Name)
		return &pb.OpUnary{Kind: &pbUnaryKind, FfiName: &name}, nil
	default:
		return nil, fmt.Errorf("biscuit: unsupported UnaryOpFunc type: %v", op.UnaryOpFunc.Type())
	}
	return &pb.OpUnary{Kind: &pbUnaryKind}, nil
}

func protoExprUnaryToTokenExprUnary(op *pb.OpUnary) (datalog.UnaryOpFunc, error) {
	var unaryOp datalog.UnaryOpFunc
	switch *op.Kind {
	case pb.OpUnary_Negate:
		unaryOp = datalog.Negate{}
	case pb.OpUnary_Parens:
		unaryOp = datalog.Parens{}
	case pb.OpUnary_Length:
		unaryOp = datalog.Length{}
	case pb.OpUnary_TypeOf:
		unaryOp = datalog.TypeOf{}
	case pb.OpUnary_Ffi:
		if op.FfiName == nil {
			return nil, errors.New("biscuit: proto OpUnary Ffi without a name")
		}
		unaryOp = datalog.Ffi{Name: datalog.String(op.GetFfiName())}
	default:
		return nil, fmt.Errorf("biscuit: unsupported proto OpUnary type: %v", op.Kind)
	}
	return unaryOp, nil
}

func tokenExprBinaryToProtoExprBinary(op datalog.BinaryOp) (*pb.OpBinary, error) {
	var pbBinaryKind pb.OpBinary_Kind
	switch op.BinaryOpFunc.Type() {
	case datalog.BinaryLessThan:
		pbBinaryKind = pb.OpBinary_LessThan
	case datalog.BinaryLessOrEqual:
		pbBinaryKind = pb.OpBinary_LessOrEqual
	case datalog.BinaryGreaterThan:
		pbBinaryKind = pb.OpBinary_GreaterThan
	case datalog.BinaryGreaterOrEqual:
		pbBinaryKind = pb.OpBinary_GreaterOrEqual
	case datalog.BinaryEqual:
		pbBinaryKind = pb.OpBinary_Equal
	case datalog.BinaryContains:
		pbBinaryKind = pb.OpBinary_Contains
	case datalog.BinaryPrefix:
		pbBinaryKind = pb.OpBinary_Prefix
	case datalog.BinarySuffix:
		pbBinaryKind = pb.OpBinary_Suffix
	case datalog.BinaryRegex:
		pbBinaryKind = pb.OpBinary_Regex
	case datalog.BinaryAdd:
		pbBinaryKind = pb.OpBinary_Add
	case datalog.BinarySub:
		pbBinaryKind = pb.OpBinary_Sub
	case datalog.BinaryMul:
		pbBinaryKind = pb.OpBinary_Mul
	case datalog.BinaryDiv:
		pbBinaryKind = pb.OpBinary_Div
	case datalog.BinaryAnd:
		pbBinaryKind = pb.OpBinary_And
	case datalog.BinaryOr:
		pbBinaryKind = pb.OpBinary_Or
	case datalog.BinaryIntersection:
		pbBinaryKind = pb.OpBinary_Intersection
	case datalog.BinaryUnion:
		pbBinaryKind = pb.OpBinary_Union
	case datalog.BinaryBitwiseAnd:
		pbBinaryKind = pb.OpBinary_BitwiseAnd
	case datalog.BinaryBitwiseOr:
		pbBinaryKind = pb.OpBinary_BitwiseOr
	case datalog.BinaryBitwiseXor:
		pbBinaryKind = pb.OpBinary_BitwiseXor
	case datalog.BinaryNotEqual:
		pbBinaryKind = pb.OpBinary_NotEqual
	case datalog.BinaryHeterogeneousEqual:
		pbBinaryKind = pb.OpBinary_HeterogeneousEqual
	case datalog.BinaryHeterogeneousNotEqual:
		pbBinaryKind = pb.OpBinary_HeterogeneousNotEqual
	case datalog.BinaryLazyAnd:
		pbBinaryKind = pb.OpBinary_LazyAnd
	case datalog.BinaryLazyOr:
		pbBinaryKind = pb.OpBinary_LazyOr
	case datalog.BinaryAll:
		pbBinaryKind = pb.OpBinary_All
	case datalog.BinaryAny:
		pbBinaryKind = pb.OpBinary_Any
	case datalog.BinaryGet:
		pbBinaryKind = pb.OpBinary_Get
	case datalog.BinaryTryOr:
		pbBinaryKind = pb.OpBinary_TryOr
	case datalog.BinaryFfi:
		pbBinaryKind = pb.OpBinary_Ffi
		name := uint64(op.BinaryOpFunc.(datalog.FfiBinary).Name)
		return &pb.OpBinary{Kind: &pbBinaryKind, FfiName: &name}, nil
	default:
		return nil, fmt.Errorf("biscuit: unsupported BinaryOpFunc type: %v", op.BinaryOpFunc.Type())
	}
	return &pb.OpBinary{Kind: &pbBinaryKind}, nil
}

func protoExprBinaryToTokenExprBinary(op *pb.OpBinary) (datalog.BinaryOpFunc, error) {
	var binaryOp datalog.BinaryOpFunc
	switch *op.Kind {
	case pb.OpBinary_LessThan:
		binaryOp = datalog.LessThan{}
	case pb.OpBinary_GreaterThan:
		binaryOp = datalog.GreaterThan{}
	case pb.OpBinary_LessOrEqual:
		binaryOp = datalog.LessOrEqual{}
	case pb.OpBinary_GreaterOrEqual:
		binaryOp = datalog.GreaterOrEqual{}
	case pb.OpBinary_Equal:
		binaryOp = datalog.Equal{}
	case pb.OpBinary_Contains:
		binaryOp = datalog.Contains{}
	case pb.OpBinary_Prefix:
		binaryOp = datalog.Prefix{}
	case pb.OpBinary_Suffix:
		binaryOp = datalog.Suffix{}
	case pb.OpBinary_Regex:
		binaryOp = datalog.Regex{}
	case pb.OpBinary_Add:
		binaryOp = datalog.Add{}
	case pb.OpBinary_Sub:
		binaryOp = datalog.Sub{}
	case pb.OpBinary_Mul:
		binaryOp = datalog.Mul{}
	case pb.OpBinary_Div:
		binaryOp = datalog.Div{}
	case pb.OpBinary_And:
		binaryOp = datalog.And{}
	case pb.OpBinary_Or:
		binaryOp = datalog.Or{}
	case pb.OpBinary_Intersection:
		binaryOp = datalog.Intersection{}
	case pb.OpBinary_Union:
		binaryOp = datalog.Union{}
	case pb.OpBinary_BitwiseAnd:
		binaryOp = datalog.BitwiseAnd{}
	case pb.OpBinary_BitwiseOr:
		binaryOp = datalog.BitwiseOr{}
	case pb.OpBinary_BitwiseXor:
		binaryOp = datalog.BitwiseXor{}
	case pb.OpBinary_NotEqual:
		binaryOp = datalog.NotEqual{}
	case pb.OpBinary_HeterogeneousEqual:
		binaryOp = datalog.HeterogeneousEqual{}
	case pb.OpBinary_HeterogeneousNotEqual:
		binaryOp = datalog.HeterogeneousNotEqual{}
	case pb.OpBinary_LazyAnd:
		binaryOp = datalog.LazyAnd{}
	case pb.OpBinary_LazyOr:
		binaryOp = datalog.LazyOr{}
	case pb.OpBinary_All:
		binaryOp = datalog.All{}
	case pb.OpBinary_Any:
		binaryOp = datalog.Any{}
	case pb.OpBinary_Get:
		binaryOp = datalog.Get{}
	case pb.OpBinary_TryOr:
		binaryOp = datalog.TryOr{}
	case pb.OpBinary_Ffi:
		if op.FfiName == nil {
			return nil, errors.New("biscuit: proto OpBinary Ffi without a name")
		}
		binaryOp = datalog.FfiBinary{Name: datalog.String(op.GetFfiName())}
	default:
		return nil, fmt.Errorf("biscuit: unsupported proto OpBinary type: %v", op.Kind)
	}
	return binaryOp, nil
}

func tokenCheckToProtoCheckV2(input datalog.Check, keys publicKeyTable) (*pb.Check, error) {
	pbQueries := make([]*pb.Rule, len(input.Queries))
	for i, query := range input.Queries {
		q, err := tokenRuleToProtoRuleV2(query, keys)
		if err != nil {
			return nil, err
		}
		pbQueries[i] = q
	}

	pbCheck := &pb.Check{
		Queries: pbQueries,
	}
	// `check if` is the default and stays unset, as other implementations do.
	switch input.Kind {
	case datalog.CheckKindOne:
	case datalog.CheckKindAll:
		pbCheck.Kind = pb.Check_All.Enum()
	case datalog.CheckKindReject:
		pbCheck.Kind = pb.Check_Reject.Enum()
	default:
		return nil, fmt.Errorf("biscuit: unsupported check kind: %d", input.Kind)
	}
	return pbCheck, nil
}

func protoCheckToTokenCheckV2(input *pb.Check, keys publicKeyTable) (*datalog.Check, error) {
	queries := make([]datalog.Rule, len(input.Queries))
	for i, query := range input.Queries {
		q, err := protoRuleToTokenRuleV2(query, keys)
		if err != nil {
			return nil, err
		}
		queries[i] = *q
	}

	check := &datalog.Check{
		Queries: queries,
	}
	switch input.GetKind() {
	case pb.Check_One:
	case pb.Check_All:
		check.Kind = datalog.CheckKindAll
	case pb.Check_Reject:
		check.Kind = datalog.CheckKindReject
	default:
		return nil, fmt.Errorf("biscuit: unsupported check kind: %s", input.GetKind())
	}
	return check, nil
}
