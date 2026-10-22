// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuittest

import (
	"cmp"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
	"github.com/stretchr/testify/require"
)

type Samples struct {
	RootPrivateKey string     `json:"root_private_key"`
	RootPublicKey  string     `json:"root_public_key"`
	TestCases      []TestCase `json:"testcases"`
}

type TestCase struct {
	Title       string                `json:"title"`
	Filename    string                `json:"filename"`
	Token       []Block               `json:"token"`
	Validations map[string]Validation `json:"validations"`
}

type Block struct {
	Symbols     []string `json:"symbols"`
	PublicKeys  []any    `json:"public_keys"`
	ExternalKey any      `json:"external_key"`
	Code        string   `json:"code"`
	Version     uint32   `json:"version"`
}

type Result struct {
	Ok  *int          `json:"Ok"`
	Err *BiscuitError `json:"Err"`
}

type BiscuitError struct {
	FailedLogic *struct {
		Unauthorized *struct {
			Policy struct {
				Allow int `json:"Allow"`
			} `json:"policy"`
			Checks []struct {
				Block *struct {
					BlockID int    `json:"block_id"`
					CheckID int    `json:"check_id"`
					Rule    string `json:"rule"`
				} `json:"Block"`
				Authorizer *struct {
					CheckID int    `json:"check_id"`
					Rule    string `json:"rule"`
				} `json:"Authorizer"`
			} `json:"checks"`
		} `json:"Unauthorized"`
		InvalidBlockRule []any `json:"InvalidBlockRule"`
	} `json:"FailedLogic"`
	Format *struct {
		Signature *struct {
			InvalidSignature string `json:"InvalidSignature"`
		} `json:"Signature"`
		BlockSignatureDeserializationError *string `json:"BlockSignatureDeserializationError"`
	} `json:"Format"`
	Execution *string `json:"Execution"`
}

// authorizerOrigin is the origin the spec assigns to authorizer rules and checks (usize::MAX).
const authorizerOrigin = math.MaxUint64

type World struct {
	Facts    []FactGroup  `json:"facts"`
	Rules    []RuleGroup  `json:"rules"`
	Checks   []CheckGroup `json:"checks"`
	Policies []string     `json:"policies"`
}

// FactGroup holds the facts derived from the same set of block origins;
// a nil origin denotes the authorizer.
type FactGroup struct {
	Origin []*uint64 `json:"origin"`
	Facts  []string  `json:"facts"`
}

type RuleGroup struct {
	Origin *uint64  `json:"origin"`
	Rules  []string `json:"rules"`
}

type CheckGroup struct {
	Origin *uint64  `json:"origin"`
	Checks []string `json:"checks"`
}

// originString prints an origin the way the authorizer does; a nil block id
// is the authorizer (usize::MAX in the reference implementation). The JSON
// lists the ids as a set, so they are sorted here, authorizer last.
func originString(ids []*uint64) string {
	ids = sortedOrigin(ids)
	parts := make([]string, len(ids))
	for i, id := range ids {
		if id == nil || *id == authorizerOrigin {
			parts[i] = "authorizer"
		} else {
			parts[i] = strconv.FormatUint(*id, 10)
		}
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// String renders the expected world in the format of Authorizer.PrintWorld:
// facts grouped by origin and rules by block, groups and entries sorted.
// Checks and policies are compared through the authorization result.
func (w World) String() string {
	var b strings.Builder

	facts := slices.Clone(w.Facts)
	for i := range facts {
		facts[i].Origin = sortedOrigin(facts[i].Origin)
	}
	slices.SortFunc(facts, func(a, b FactGroup) int { return compareOrigins(a.Origin, b.Origin) })
	if len(facts) > 0 {
		b.WriteString("// Facts:\n")
	}
	for _, group := range facts {
		fmt.Fprintf(&b, "// origin: %s\n", originString(group.Origin))
		entries := slices.Clone(group.Facts)
		sort.Strings(entries)
		for _, f := range entries {
			fmt.Fprintf(&b, "%s;\n", f)
		}
	}

	rules := slices.Clone(w.Rules)
	slices.SortFunc(rules, func(a, b RuleGroup) int { return compareOrigins([]*uint64{a.Origin}, []*uint64{b.Origin}) })
	if len(rules) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("// Rules:\n")
	}
	for _, group := range rules {
		fmt.Fprintf(&b, "// origin: %s\n", strings.Trim(originString([]*uint64{group.Origin}), "[]"))
		entries := slices.Clone(group.Rules)
		sort.Strings(entries)
		for _, r := range entries {
			fmt.Fprintf(&b, "%s;\n", r)
		}
	}
	return b.String()
}

func sortedOrigin(ids []*uint64) []*uint64 {
	ids = slices.Clone(ids)
	slices.SortFunc(ids, func(a, b *uint64) int { return compareOrigins([]*uint64{a}, []*uint64{b}) })
	return ids
}

// compareOrigins orders origins by block id, the authorizer last.
func compareOrigins(a, b []*uint64) int {
	value := func(id *uint64) uint64 {
		if id == nil {
			return authorizerOrigin
		}
		return *id
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := cmp.Compare(value(a[i]), value(b[i])); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(a), len(b))
}

type Validation struct {
	World          *World   `json:"world"`
	Result         Result   `json:"result"`
	AuthorizerCode string   `json:"authorizer_code"`
	RevocationIds  []string `json:"revocation_ids"`
}

// Support for newer datalog versions lands incrementally. Samples are gated
// on the block version they exercise: bumping biscuit.MaxSchemaVersion enables
// the matching samples here with no other change.
//
// unsupported lists the samples inside the supported version range that
// cannot pass yet; each entry is removed by the change that closes the gap.
var unsupported = map[string]string{}

func maxBlockVersion(c TestCase) uint32 {
	var v uint32
	for _, b := range c.Token {
		if b.Version > v {
			v = b.Version
		}
	}
	return v
}

func CheckSample(root_key ed25519.PublicKey, c TestCase, t *testing.T) {
	fmt.Printf("Checking sample %s\n", c.Filename)
	b, err := os.ReadFile("./data/current/" + c.Filename)
	require.NoError(t, err)

	if v := maxBlockVersion(c); v > biscuit.MaxSchemaVersion {
		// The spec requires refusing blocks newer than the supported range.
		_, err := biscuit.Unmarshal(b)
		require.Error(t, err)
		t.Skipf("block version %d > MaxSchemaVersion %d", v, biscuit.MaxSchemaVersion)
	}
	if reason, ok := unsupported[c.Filename]; ok {
		t.Skipf("unsupported: %s", reason)
	}

	token, err := biscuit.Unmarshal(b)

	if err == nil {
		fmt.Printf("  Parsed file %s\n", c.Filename)
		// this sample uses a tampered biscuit file on purpose
		if c.Filename != "test006_reordered_blocks.bc" {
			CompareBlocks(*token, c.Token, t)
		}

		for _, v := range c.Validations {
			CompareResult(root_key, c.Filename, *token, v, t)
		}

	} else {
		fmt.Println(err)
		fmt.Println("  Parsing failed, all validations must be errors")
		for _, v := range c.Validations {
			require.Nil(t, v.Result.Ok)
		}
	}
}

func CompareBlocks(token biscuit.Biscuit, blocks []Block, t *testing.T) {
	sample := token.Code()
	p := parser.New()

	rng := rand.Reader
	_, privateRoot, _ := ed25519.GenerateKey(rng)
	authority, err := p.Block(blocks[0].Code, nil)
	require.NoError(t, err)
	builder := biscuit.NewBuilder(privateRoot)
	require.NoError(t, builder.AddBlock(authority))
	r, err := builder.Build()
	require.NoError(t, err)
	rebuilt := *r

	for _, b := range blocks[1:] {
		parsed, err := p.Block(b.Code, nil)
		require.NoError(t, err)
		builder := rebuilt.CreateBlock()
		require.NoError(t, builder.AddBlock(parsed))
		r, err := rebuilt.Append(rng, builder.Build())
		require.NoError(t, err)
		rebuilt = *r
	}

	require.Equal(t, sample, rebuilt.Code())
}

// sampleExternFuncs mirrors the extern functions registered by the sample
// generator (biscuit-rust examples/testcases.rs).
var sampleExternFuncs = map[string]biscuit.ExternFunc{
	"test": func(left biscuit.Term, right biscuit.Term) (biscuit.Term, error) {
		if right == nil {
			return left, nil
		}
		l, lok := left.(biscuit.String)
		r, rok := right.(biscuit.String)
		if !lok || !rok {
			return nil, errors.New("unsupported operands")
		}
		if l == r {
			return biscuit.String("equal strings"), nil
		}
		return biscuit.String("different strings"), nil
	},
}

func CompareResult(root_key ed25519.PublicKey, filename string, token biscuit.Biscuit, v Validation, t *testing.T) {
	p := parser.New()
	authorizer_code, err := p.Authorizer(v.AuthorizerCode, nil)
	require.NoError(t, err)
	authorizer, err := token.AuthorizerFrom(biscuit.RootKey(root_key), biscuit.WithExternFuncs(sampleExternFuncs))

	if err != nil {
		CompareError(err, v.Result.Err, t)
	} else {
		authorizer.AddAuthorizer(authorizer_code)
		err = authorizer.Authorize()
		if err != nil {
			CompareError(err, v.Result.Err, t)
		} else {
			require.NotNil(t, v.Result.Ok)
		}
		// The world is null when the reference implementation rejected the token outright.
		if v.World != nil {
			require.Equal(t, v.World.String(), authorizer.PrintWorld())
		}
	}
}

func CompareError(authorization_error error, sample_error *BiscuitError, t *testing.T) {
	error_string := authorization_error.Error()
	if sample_error.Format != nil {
		require.Equal(t, error_string, "biscuit: invalid signature")
	} else if sample_error.FailedLogic != nil {
		if sample_error.FailedLogic.Unauthorized != nil {
			// todo check the block and check ids (if there is a single failed check, because the lib only reports one)
			require.Regexp(t, "^biscuit: verification failed: failed to verify", error_string)
		} else if sample_error.FailedLogic.InvalidBlockRule != nil {
			// todo extract the block number
			require.Regexp(t, "^biscuit: verification failed: failed to verify", error_string)
		} else {
			require.Fail(t, error_string)
		}
	} else if sample_error.Execution != nil {
		require.ErrorIs(t, authorization_error, biscuit.ErrExecution)
		switch *sample_error.Execution {
		case "Overflow":
			require.ErrorIs(t, authorization_error, datalog.ErrInt64Overflow)
		case "ShadowedVariable":
			require.ErrorIs(t, authorization_error, datalog.ErrShadowedVariable)
		case "InvalidType":
			// Type errors have no sentinel in the datalog package.
		default:
			require.Fail(t, "unknown execution error kind", *sample_error.Execution)
		}
	} else {
		fmt.Println(sample_error)
		require.Fail(t, error_string)
	}
}

func TestReadSamples(t *testing.T) {
	b, err := os.ReadFile("./data/current/samples.json")
	require.NoError(t, err)
	var samples Samples
	err = json.Unmarshal(b, &samples)
	require.NoError(t, err)

	root_key, err := hex.DecodeString(samples.RootPublicKey)
	require.NoError(t, err)
	fmt.Printf("Checking %d samples\n", len(samples.TestCases))
	for _, v := range samples.TestCases {
		t.Run(v.Filename, func(t *testing.T) { CheckSample(root_key, v, t) })
	}

}
