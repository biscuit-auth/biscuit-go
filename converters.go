// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"fmt"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
	"google.golang.org/protobuf/proto"
)

// tokenBlockToProtoBlock serializes a block. keys is the key table of the
// token before this block; the keys the block introduces come after.
func tokenBlockToProtoBlock(input *Block, keys publicKeyTable) (*pb.Block, error) {
	keys = keys.with(input.publicKeys...)
	out := &pb.Block{
		Symbols: *input.symbols,
		Context: proto.String(input.context),
		Version: proto.Uint32(input.version),
	}
	for _, k := range input.publicKeys {
		out.PublicKeys = append(out.PublicKeys, tokenPublicKeyToProtoPublicKey(k))
	}
	var err error
	if out.Scope, err = tokenScopesToProtoScopes(input.scopes, keys); err != nil {
		return nil, err
	}

	facts := input.facts
	if facts != nil {
		out.FactsV2 = make([]*pb.FactV2, len(*facts))
		var err error
		for i, fact := range *facts {
			out.FactsV2[i], err = tokenFactToProtoFactV2(fact)
			if err != nil {
				return nil, err
			}
		}
	}

	rules := input.rules
	if rules != nil {
		out.RulesV2 = make([]*pb.RuleV2, len(rules))
		for i, rule := range rules {
			r, err := tokenRuleToProtoRuleV2(rule, keys)
			if err != nil {
				return nil, err
			}
			out.RulesV2[i] = r
		}
	}

	checks := input.checks
	if checks != nil {
		out.ChecksV2 = make([]*pb.CheckV2, len(checks))
		for i, check := range checks {
			c, err := tokenCheckToProtoCheckV2(check, keys)
			if err != nil {
				return nil, err
			}
			out.ChecksV2[i] = c
		}
	}

	return out, nil
}

// protoBlockToTokenBlock deserializes a block. keys is the key table of the
// token before this block; the keys the block introduces come after.
func protoBlockToTokenBlock(input *pb.Block, keys publicKeyTable) (*Block, error) {
	symbols := datalog.SymbolTable(input.Symbols)

	var facts datalog.FactSet
	var rules []datalog.Rule
	var checks []datalog.Check

	var publicKeys []datalog.PublicKey
	for _, pbKey := range input.PublicKeys {
		key, err := protoPublicKeyToTokenPublicKey(pbKey)
		if err != nil {
			return nil, fmt.Errorf("biscuit: failed to convert proto block to token block: %w", err)
		}
		publicKeys = append(publicKeys, key)
	}
	keys = keys.with(publicKeys...)

	scopes, err := protoScopesToTokenScopes(input.Scope, keys)
	if err != nil {
		return nil, fmt.Errorf("biscuit: failed to convert proto block to token block: %w", err)
	}

	if input.GetVersion() < MinSchemaVersion {
		return nil, fmt.Errorf(
			"biscuit: failed to convert proto block to token block: block version: %d < library version %d",
			input.GetVersion(),
			MinSchemaVersion,
		)
	}
	if input.GetVersion() > MaxSchemaVersion {
		return nil, fmt.Errorf(
			"biscuit: failed to convert proto block to token block: block version: %d > library version %d",
			input.GetVersion(),
			MaxSchemaVersion,
		)
	}

	switch input.GetVersion() {
	case blockVersion3_0, blockVersion3_1:
		facts = make(datalog.FactSet, len(input.FactsV2))
		rules = make([]datalog.Rule, len(input.RulesV2))
		checks = make([]datalog.Check, len(input.ChecksV2))

		for i, pbFact := range input.FactsV2 {
			f, err := protoFactToTokenFactV2(pbFact)
			if err != nil {
				return nil, err
			}
			facts[i] = *f
		}

		for i, pbRule := range input.RulesV2 {
			r, err := protoRuleToTokenRuleV2(pbRule, keys)
			if err != nil {
				return nil, err
			}
			rules[i] = *r
		}

		for i, pbCheck := range input.ChecksV2 {
			c, err := protoCheckToTokenCheckV2(pbCheck, keys)
			if err != nil {
				return nil, err
			}
			checks[i] = *c
		}
	default:
		return nil, fmt.Errorf("biscuit: failed to convert proto block to token block: unsupported version: %d", input.GetVersion())
	}

	if required := schemaVersion(scopes, rules, checks); input.GetVersion() < required {
		return nil, fmt.Errorf(
			"biscuit: failed to convert proto block to token block: block version %d uses features of version %d",
			input.GetVersion(),
			required,
		)
	}

	return &Block{
		symbols:    &symbols,
		facts:      &facts,
		rules:      rules,
		checks:     checks,
		scopes:     scopes,
		publicKeys: publicKeys,
		context:    input.GetContext(),
		version:    input.GetVersion(),
	}, nil
}

/*func tokenSignatureToProtoSignature(ts *sig.TokenSignature) *pb.Signature {
	params, z := ts.Encode()
	return &pb.Signature{
		Parameters: params,
		Z:          z,
	}
}

func protoSignatureToTokenSignature(ps *pb.Signature) (*sig.TokenSignature, error) {
	return sig.Decode(ps.Parameters, ps.Z)
}*/
