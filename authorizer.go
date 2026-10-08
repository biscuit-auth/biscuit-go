// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"errors"
	"fmt"
	"strings"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
	"google.golang.org/protobuf/proto"
)

var (
	ErrMissingSymbols   = errors.New("biscuit: missing symbols")
	ErrPolicyDenied     = errors.New("biscuit: denied by policy")
	ErrNoMatchingPolicy = errors.New("biscuit: denied by no matching policies")
	// ErrExecution wraps an error raised while evaluating an expression
	// (integer overflow, division by zero, type mismatch). Authorization
	// stops at the first one, as the spec requires.
	ErrExecution = errors.New("biscuit: execution error")
)

type Authorizer interface {
	AddAuthorizer(a ParsedAuthorizer)
	AddBlock(b ParsedBlock)
	AddFact(fact Fact)
	AddRule(rule Rule)
	AddCheck(check Check)
	AddPolicy(policy Policy)
	// AddScope sets the default scope of the authorizer's rules, checks
	// and policies; see Scope.
	AddScope(scope Scope)
	Authorize() error
	Query(rule Rule) (FactSet, error)
	Biscuit() *Biscuit
	Reset()
	PrintWorld() string
	LoadPolicies([]byte) error
	SerializePolicies() ([]byte, error)
}

type authorizer struct {
	biscuit     *Biscuit
	baseWorld   *datalog.World
	world       *datalog.World
	baseSymbols *datalog.SymbolTable
	symbols     *datalog.SymbolTable

	checks   []Check
	policies []Policy
	scopes   []Scope

	// blocksByKey maps the public key of a third-party block, as printed
	// by datalog.PublicKey.String, to the blocks it signed; `trusting <key>`
	// resolves to those blocks.
	blocksByKey map[string][]datalog.BlockID

	externs datalog.ExternFuncs

	dirty bool
}

var _ Authorizer = (*authorizer)(nil)

type AuthorizerOption func(w *authorizer)

func WithWorldOptions(opts ...datalog.WorldOption) AuthorizerOption {
	return func(a *authorizer) {
		a.baseWorld = datalog.NewWorld(opts...)
	}
}

// ExternFunc is a function that datalog v3.3 expressions call with
// `$left.extern::name()` (right is nil) or `$left.extern::name($right)`.
// It returns the value of the call.
type ExternFunc func(left Term, right Term) (Term, error)

// WithExternFuncs registers the functions available to extern:: calls, by
// name. A call to a name that is not registered fails the check or rule that
// makes it with ErrExecution.
func WithExternFuncs(funcs map[string]ExternFunc) AuthorizerOption {
	return func(a *authorizer) {
		for name, f := range funcs {
			a.externs[name] = wrapExternFunc(f)
		}
	}
}

func wrapExternFunc(f ExternFunc) datalog.ExternFunc {
	return func(symbols *datalog.SymbolTable, left datalog.Term, right datalog.Term) (datalog.Term, error) {
		l, err := fromDatalogID(symbols, left)
		if err != nil {
			return nil, err
		}
		var r Term
		if right != nil {
			if r, err = fromDatalogID(symbols, right); err != nil {
				return nil, err
			}
		}
		res, err := f(l, r)
		if err != nil {
			return nil, err
		}
		if res == nil {
			return nil, errors.New("biscuit: extern function returned no value")
		}
		return res.convert(symbols), nil
	}
}

func NewVerifier(b *Biscuit, opts ...AuthorizerOption) (Authorizer, error) {
	a := &authorizer{
		biscuit:     b,
		baseWorld:   datalog.NewWorld(),
		baseSymbols: defaultSymbolTable.Clone(),
		checks:      []Check{},
		policies:    []Policy{},
		blocksByKey: map[string][]datalog.BlockID{},
		externs:     datalog.ExternFuncs{},
	}

	for _, opt := range opts {
		opt(a)
	}
	datalog.WithExternFuncs(a.externs)(a.baseWorld)
	for i, block := range b.blocks {
		if block.externalKey != nil {
			key := block.externalKey.String()
			a.blocksByKey[key] = append(a.blocksByKey[key], datalog.BlockID(i+1))
		}
	}

	a.world = a.baseWorld.Clone()
	a.symbols = a.baseSymbols.Clone()

	return a, nil
}

func (v *authorizer) AddAuthorizer(a ParsedAuthorizer) {
	v.AddBlock(a.Block)
	for _, p := range a.Policies {
		v.AddPolicy(p)
	}
}

func (v *authorizer) AddBlock(block ParsedBlock) {
	for _, f := range block.Facts {
		v.AddFact(f)
	}
	for _, r := range block.Rules {
		v.AddRule(r)
	}
	for _, c := range block.Checks {
		v.AddCheck(c)
	}
	for _, s := range block.Scopes {
		v.AddScope(s)
	}
}

func (v *authorizer) AddFact(fact Fact) {
	v.world.AddFact(authorizerOrigin, fact.convert(v.symbols))
}

func (v *authorizer) AddRule(rule Rule) {
	r := rule.convert(v.symbols)
	v.world.AddRule(datalog.AuthorizerBlockID, v.trustedOrigins(r.Scopes, v.authorizerTrustedOrigins(), datalog.AuthorizerBlockID), r)
}

func (v *authorizer) AddScope(scope Scope) {
	v.scopes = append(v.scopes, scope)
}

// authorizerTrustedOrigins is the default scope of the authorizer's rules,
// checks and policies: its own scopes, or the authority block and itself.
func (v *authorizer) authorizerTrustedOrigins() datalog.TrustedOrigins {
	return v.trustedOrigins(v.scopes, datalog.DefaultTrustedOrigins(), datalog.AuthorizerBlockID)
}

func (v *authorizer) trustedOrigins(scopes []datalog.Scope, defaults datalog.TrustedOrigins, current datalog.BlockID) datalog.TrustedOrigins {
	return datalog.TrustedOriginsFromScopes(scopes, defaults, current, v.blocksByKey)
}

func (v *authorizer) AddCheck(check Check) {
	v.checks = append(v.checks, check)
}

func (v *authorizer) AddPolicy(policy Policy) {
	v.policies = append(v.policies, policy)
}

// authorizerOrigin is the origin of the facts the authorizer adds itself.
var authorizerOrigin = datalog.NewOrigin(datalog.AuthorizerBlockID)

func (v *authorizer) Authorize() error {
	// if we load facts from the verifier before
	// the token's fact and rules, we might get inconsistent symbols
	// token ements should first be converted to builder elements
	// with the token's symbol table, then converted back
	// with the verifier's symbol table
	blocks := append([]*Block{v.biscuit.authority}, v.biscuit.blocks...)
	blockTrusted := make([]datalog.TrustedOrigins, len(blocks))
	for i, block := range blocks {
		blockID := datalog.BlockID(i)
		blockTrusted[i] = v.trustedOrigins(block.scopes, datalog.DefaultTrustedOrigins(), blockID)
		symbols := block.symbolTable(v.biscuit.symbols)
		for _, fact := range *block.facts {
			f, err := fromDatalogFact(symbols, fact)
			if err != nil {
				return fmt.Errorf("biscuit: verification failed: %s", err)
			}
			v.world.AddFact(datalog.NewOrigin(blockID), f.convert(v.symbols))
		}

		for _, rule := range block.rules {
			r, err := fromDatalogRule(symbols, rule)
			if err != nil {
				return fmt.Errorf("biscuit: verification failed: %s", err)
			}
			dlRule := r.convert(v.symbols)
			v.world.AddRule(blockID, v.trustedOrigins(dlRule.Scopes, blockTrusted[i], blockID), dlRule)
		}
	}

	if err := v.world.Run(v.symbols); err != nil {
		return err
	}
	v.dirty = true

	var errs []error
	debug := datalog.SymbolDebugger{SymbolTable: v.symbols}
	authorizerTrusted := v.authorizerTrustedOrigins()

	for i, check := range v.checks {
		c := check.convert(v.symbols)
		successful, err := v.checkPasses(c, datalog.AuthorizerBlockID, authorizerTrusted)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrExecution, err)
		}
		if !successful {
			errs = append(errs, fmt.Errorf("failed to verify check #%d: %s", i, debug.Check(c)))
		}
	}

	for i, check := range v.biscuit.authority.checks {
		ch, err := fromDatalogCheck(v.biscuit.authority.symbolTable(v.biscuit.symbols), check)
		if err != nil {
			return fmt.Errorf("biscuit: verification failed: %s", err)
		}
		c := ch.convert(v.symbols)

		successful, err := v.checkPasses(c, 0, blockTrusted[0])
		if err != nil {
			return fmt.Errorf("%w: %w", ErrExecution, err)
		}
		if !successful {
			errs = append(errs, fmt.Errorf("failed to verify block 0 check #%d: %s", i, debug.Check(c)))
		}
	}

	policyMatched := false
	policyResult := ErrPolicyDenied
	for _, policy := range v.policies {
		if policyMatched {
			break
		}
		for _, query := range policy.Queries {
			q := query.convert(v.symbols)
			res, err := v.world.QueryRule(q, datalog.AuthorizerBlockID, v.trustedOrigins(q.Scopes, authorizerTrusted, datalog.AuthorizerBlockID), v.symbols)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrExecution, err)
			}
			if len(*res) != 0 {
				switch policy.Kind {
				case PolicyKindAllow:
					policyResult = nil
					policyMatched = true
				case PolicyKindDeny:
					policyResult = ErrPolicyDenied
					policyMatched = true
				}
				break
			}
		}
	}

	for i, block := range v.biscuit.blocks {
		blockID := datalog.BlockID(i + 1)
		for j, check := range block.checks {
			ch, err := fromDatalogCheck(block.symbolTable(v.biscuit.symbols), check)
			if err != nil {
				return fmt.Errorf("biscuit: verification failed: %s", err)
			}
			c := ch.convert(v.symbols)

			successful, err := v.checkPasses(c, blockID, blockTrusted[blockID])
			if err != nil {
				return fmt.Errorf("%w: %w", ErrExecution, err)
			}
			if !successful {
				errs = append(errs, fmt.Errorf("failed to verify block #%d check #%d: %s", blockID, j, debug.Check(c)))
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

	v.baseWorld = v.world.Clone()
	v.baseSymbols = v.symbols.Clone()

	if policyMatched {
		return policyResult
	} else {
		return ErrNoMatchingPolicy
	}
}

// checkPasses evaluates the queries of a check from block blockID: a check
// passes when one of its queries does, under the semantics of its kind. Each
// query reads the facts of its own scopes, or of defaults.
func (v *authorizer) checkPasses(c datalog.Check, blockID datalog.BlockID, defaults datalog.TrustedOrigins) (bool, error) {
	for _, query := range c.Queries {
		trusted := v.trustedOrigins(query.Scopes, defaults, blockID)
		switch c.Kind {
		case datalog.CheckKindAll:
			ok, err := v.world.QueryMatchAll(query, trusted, v.symbols)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		case datalog.CheckKindReject:
			res, err := v.world.QueryRule(query, blockID, trusted, v.symbols)
			if err != nil {
				return false, err
			}
			if len(*res) == 0 {
				return true, nil
			}
		default:
			res, err := v.world.QueryRule(query, blockID, trusted, v.symbols)
			if err != nil {
				return false, err
			}
			if len(*res) != 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

func (v *authorizer) Query(rule Rule) (FactSet, error) {
	if err := v.world.Run(v.symbols); err != nil {
		return nil, err
	}
	v.dirty = true

	// Without scopes a query reads the authority block and the authorizer,
	// like the reference implementation; facts of later blocks are not visible.
	q := rule.convert(v.symbols)
	facts, err := v.world.QueryRule(q, datalog.AuthorizerBlockID, v.trustedOrigins(q.Scopes, datalog.DefaultTrustedOrigins(), datalog.AuthorizerBlockID), v.symbols)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExecution, err)
	}

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

func (v *authorizer) Biscuit() *Biscuit {
	return v.biscuit
}

// Returns the content of the Datalog environment
// This will be empty until the call to Authorize(), where
// facts, rules and checks will be evaluated
func (v *authorizer) PrintWorld() string {
	debug := datalog.SymbolDebugger{
		SymbolTable: v.symbols,
	}

	return debug.World(v.world)
}

func (v *authorizer) Reset() {
	v.world = v.baseWorld.Clone()
	v.symbols = v.baseSymbols.Clone()
	v.checks = []Check{}
	v.policies = []Policy{}
	v.scopes = nil
	v.dirty = false
}

func (v *authorizer) LoadPolicies(authorizerPolicies []byte) error {
	pbPolicies := &pb.AuthorizerPolicies{}
	if err := proto.Unmarshal(authorizerPolicies, pbPolicies); err != nil {
		return fmt.Errorf("verifier: failed to load policies: %w", err)
	}

	switch pbPolicies.GetVersion() {
	case blockVersion3_0, blockVersion3_1, blockVersion3_2, blockVersion3_3:
		return v.loadPoliciesV2(pbPolicies)
	default:
		return fmt.Errorf("verifier: unsupported policies version %d", pbPolicies.GetVersion())
	}
}

func (v *authorizer) loadPoliciesV2(pbPolicies *pb.AuthorizerPolicies) error {
	policySymbolTable := datalog.SymbolTable(pbPolicies.Symbols)
	v.symbols = v.baseSymbols.Clone()
	v.symbols.Extend(&policySymbolTable)

	for _, pbFact := range pbPolicies.Facts {
		fact, err := protoFactToTokenFactV2(pbFact)
		if err != nil {
			return fmt.Errorf("verifier: load policies v1: failed to convert datalog fact: %w", err)
		}
		v.world.AddFact(authorizerOrigin, *fact)
	}

	for _, pbRule := range pbPolicies.Rules {
		rule, err := protoRuleToTokenRuleV2(pbRule, nil)
		if err != nil {
			return fmt.Errorf("verifier: load policies v1: failed to convert datalog rule: %w", err)
		}
		v.world.AddRule(datalog.AuthorizerBlockID, v.trustedOrigins(rule.Scopes, v.authorizerTrustedOrigins(), datalog.AuthorizerBlockID), *rule)
	}

	v.checks = make([]Check, len(pbPolicies.Checks))
	for i, pbCheck := range pbPolicies.Checks {
		dlCheck, err := protoCheckToTokenCheckV2(pbCheck, nil)
		if err != nil {
			return fmt.Errorf("verifier: load policies v1: failed to convert datalog check: %w", err)
		}
		check, err := fromDatalogCheck(v.symbols, *dlCheck)
		if err != nil {
			return fmt.Errorf("verifier: load policies v1: failed to convert check: %w", err)
		}
		v.checks[i] = *check
	}

	v.policies = make([]Policy, len(pbPolicies.Policies))
	for i, pbPolicy := range pbPolicies.Policies {
		policy := Policy{}
		switch *pbPolicy.Kind {
		case pb.Policy_Allow:
			policy.Kind = PolicyKindAllow
		case pb.Policy_Deny:
			policy.Kind = PolicyKindDeny
		default:
			return fmt.Errorf("verifier: load policies v1: unsupported proto policy kind %v", pbPolicy.Kind)
		}

		policy.Queries = make([]Rule, len(pbPolicy.Queries))
		for j, pbRule := range pbPolicy.Queries {
			dlRule, err := protoRuleToTokenRuleV2(pbRule, nil)
			if err != nil {
				return fmt.Errorf("verifier: load policies v1: failed to convert datalog policy rule: %w", err)
			}

			rule, err := fromDatalogRule(v.symbols, *dlRule)
			if err != nil {
				return fmt.Errorf("verifier: load policies v1: failed to convert policy rule: %w", err)
			}
			policy.Queries[j] = *rule
		}
		v.policies[i] = policy
	}

	return nil
}

func (v *authorizer) SerializePolicies() ([]byte, error) {
	if v.dirty {
		return nil, errors.New("verifier: can't serialize after world has been run")
	}

	// Only what the authorizer added itself is saved; the token is not part
	// of the policies.
	var protoFacts []*pb.Fact
	for _, group := range v.world.Facts() {
		if !group.Origin.Equal(authorizerOrigin) {
			continue
		}
		for _, fact := range group.Facts {
			protoFact, err := tokenFactToProtoFactV2(fact)
			if err != nil {
				return nil, fmt.Errorf("verifier: failed to convert fact: %w", err)
			}
			protoFacts = append(protoFacts, protoFact)
		}
	}

	var protoRules []*pb.Rule
	for _, br := range v.world.Rules() {
		if br.BlockID != datalog.AuthorizerBlockID {
			continue
		}
		protoRule, err := tokenRuleToProtoRuleV2(br.Rule, nil)
		if err != nil {
			return nil, fmt.Errorf("verifier: failed to convert rule: %w", err)
		}
		protoRules = append(protoRules, protoRule)
	}

	protoChecks := make([]*pb.Check, len(v.checks))
	for i, check := range v.checks {
		protoCheck, err := tokenCheckToProtoCheckV2(check.convert(v.symbols), nil)
		if err != nil {
			return nil, fmt.Errorf("verifier: failed to convert check: %w", err)
		}
		protoChecks[i] = protoCheck
	}

	protoPolicies := make([]*pb.Policy, len(v.policies))
	for i, policy := range v.policies {
		protoPolicy := &pb.Policy{}
		switch policy.Kind {
		case PolicyKindAllow:
			kind := pb.Policy_Allow
			protoPolicy.Kind = &kind
		case PolicyKindDeny:
			kind := pb.Policy_Deny
			protoPolicy.Kind = &kind
		default:
			return nil, fmt.Errorf("verifier: unsupported policy kind %v", policy.Kind)
		}

		protoPolicy.Queries = make([]*pb.Rule, len(policy.Queries))
		for j, rule := range policy.Queries {
			protoRule, err := tokenRuleToProtoRuleV2(rule.convert(v.symbols), nil)
			if err != nil {
				return nil, fmt.Errorf("verifier: failed to convert policy rule: %w", err)
			}
			protoPolicy.Queries[j] = protoRule
		}

		protoPolicies[i] = protoPolicy
	}

	version := MaxSchemaVersion
	return proto.Marshal(&pb.AuthorizerPolicies{
		Symbols:  *v.symbols.Clone(),
		Version:  proto.Uint32(version),
		Facts:    protoFacts,
		Rules:    protoRules,
		Checks:   protoChecks,
		Policies: protoPolicies,
	})
}
