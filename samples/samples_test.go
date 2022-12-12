package biscuittest

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/stretchr/testify/require"
)

type sampleVerifier struct {
	biscuit.Authorizer
}

func (s *sampleVerifier) AddOperation(op string) {
	s.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "operation",
		IDs:  []biscuit.Term{biscuit.String(op)}}},
	)
}

func (s *sampleVerifier) AddResource(res string) {
	s.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "resource",
		IDs:  []biscuit.Term{biscuit.String(res)}}},
	)
}

func (s *sampleVerifier) SetTime(t time.Time) {
	s.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "time",
		IDs:  []biscuit.Term{biscuit.Date(t)}}},
	)
}

var versions = []string{"v2"}

func TestSample1_Basic(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test1_basic.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			pubkey := loadRootPublicKey(t, v)

			ve, err := b.Authorizer(pubkey)
			require.NoError(t, err)

			verifier := &sampleVerifier{ve}

			verifier.AddOperation("read")
			verifier.AddResource("file1")
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Authorize())

			ve, err = b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)
			verifier = &sampleVerifier{ve}
			verifier.AddOperation("read")
			verifier.AddResource("file2")
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Authorize())

			ve, err = b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)
			verifier = &sampleVerifier{ve}
			verifier.AddOperation("write")
			verifier.AddResource("file1")
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, verifier.Authorize())

			s, err := b.Serialize()
			require.NoError(t, err)
			require.Equal(t, len(token), len(s))
		})
	}
}

func TestSample2_DifferentRootKey(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test2_different_root_key.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Authorizer(loadRootPublicKey(t, v))
			require.Equal(t, biscuit.ErrInvalidSignature, err)
			require.Nil(t, v)
		})
	}
}

func TestSample3_InvalidSignatureFormat(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test3_invalid_signature_format.bc")

			b, err := biscuit.Unmarshal(token)

			require.Equal(t, biscuit.ErrInvalidSignatureSize, err)
			require.Nil(t, b)
		})
	}
}

func TestSample4_RandomBlock(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test4_random_block.bc")

			_, err := biscuit.Unmarshal(token)
			// FIXME: how to create a protobuf error here to compare?
			//require.Equal(t, errors.New("cannot parse invalid wire-format data"), err)
			require.Error(t, err)
		})
	}
}

func TestSample5_InvalidSignature(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test5_invalid_signature.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			verifier, err := b.Authorizer(loadRootPublicKey(t, v))
			require.Equal(t, biscuit.ErrInvalidSignature, err)
			require.Nil(t, verifier)
		})
	}
}

func TestSample6_ReorderedBlocks(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test6_reordered_blocks.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			verifier, err := b.Authorizer(loadRootPublicKey(t, v))
			require.Equal(t, biscuit.ErrInvalidSignature, err)
			require.Nil(t, verifier)
		})
	}
}

func TestSample7_ScopedRules(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test7_scoped_rules.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)
			verifier := &sampleVerifier{v}

			verifier.AddResource("file2")
			verifier.AddOperation("read")

			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			res := verifier.Authorize()
			require.Equal(t, errors.New("biscuit: verification failed: failed to verify block #1 check #0: check if resource($0), operation(\"read\"), right($0, \"read\")"), res)
		})
	}
}

func TestSample8_ScopedChecks(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test8_scoped_checks.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)
			verifier := &sampleVerifier{v}

			verifier.AddResource("file2")
			verifier.AddOperation("read")

			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			res := verifier.Authorize()
			require.Equal(t, errors.New("biscuit: verification failed: failed to verify block #1 check #0: check if resource($0), operation(\"read\"), right($0, \"read\")"), res)
		})
	}
}

func TestSample9_ExpiredToken(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test9_expired_token.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)

			verifier := &sampleVerifier{v}

			verifier.AddOperation("read")
			verifier.AddResource("file1")
			verifier.SetTime(time.Now())
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, verifier.Authorize())

			verifier.Reset()
			expireTime, err := time.Parse(time.RFC3339, "2018-12-20T01:00:00+01:00")
			require.NoError(t, err)

			verifier.AddOperation("read")
			verifier.AddResource("file1")
			verifier.SetTime(expireTime)
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Authorize())
		})
	}
}

func TestSample10_AuthorizerScope(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test10_authorizer_scope.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)

			verifier := &sampleVerifier{v}

			verifier.AddOperation("read")
			verifier.AddResource("file2")

			verifierCheck := biscuit.Check{
				Queries: []biscuit.Rule{
					{
						Head: biscuit.Predicate{
							Name: "check1",
							IDs:  []biscuit.Term{biscuit.Variable("0"), biscuit.Variable("1")},
						},
						Body: []biscuit.Predicate{
							{Name: "right", IDs: []biscuit.Term{biscuit.Variable("0"), biscuit.Variable("1")}},
							{Name: "resource", IDs: []biscuit.Term{biscuit.Variable("0")}},
							{Name: "operation", IDs: []biscuit.Term{biscuit.Variable("1")}},
						},
					},
				},
			}

			verifier.AddCheck(verifierCheck)

			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			res := verifier.Authorize()
			require.Equal(t, errors.New("biscuit: verification failed: failed to verify check #0: check if right($0, $1), resource($0), operation($1)"), res)

		})
	}
}

func TestSample11_Authorizer_AuthorityChecks(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test11_authorizer_authority_caveats.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			ve, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)

			verifierCheck := biscuit.Check{
				Queries: []biscuit.Rule{
					{
						Head: biscuit.Predicate{
							Name: "caveat1",
							IDs:  []biscuit.Term{biscuit.Variable("0"), biscuit.Variable("1")},
						},
						Body: []biscuit.Predicate{
							{Name: "right", IDs: []biscuit.Term{biscuit.Variable("0"), biscuit.Variable("1")}},
							{Name: "resource", IDs: []biscuit.Term{biscuit.Variable("0")}},
							{Name: "operation", IDs: []biscuit.Term{biscuit.Variable("1")}},
						},
					},
				},
			}

			verifier := &sampleVerifier{ve}

			verifier.AddOperation("read")
			verifier.AddResource("file1")
			verifier.AddCheck(verifierCheck)
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Authorize())

			ve, err = b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)
			verifier = &sampleVerifier{ve}
			verifier.AddOperation("write")
			verifier.AddResource("file1")
			verifier.AddCheck(verifierCheck)
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, verifier.Authorize())

			ve, err = b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)
			verifier = &sampleVerifier{ve}
			verifier.AddOperation("read")
			verifier.AddResource("/another/file1")
			verifier.AddCheck(verifierCheck)
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, verifier.Authorize())
		})
	}
}

func TestSample12_AuthorityChecks(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test12_authority_caveats.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			ve, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)
			verifier := &sampleVerifier{ve}

			verifier.AddResource("file1")
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Authorize())

			ve, err = b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)
			verifier = &sampleVerifier{ve}
			verifier.AddResource("file1")
			verifier.AddOperation("anything")
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Authorize())

			ve, err = b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)
			verifier = &sampleVerifier{ve}
			verifier.AddResource("file2")
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, verifier.Authorize())
		})
	}
}

func TestSample13_BlockRules(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test13_block_rules.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			ve, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)
			verifier := &sampleVerifier{ve}

			verifier.AddResource("file1")
			verifier.SetTime(time.Now())
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Authorize())

			file1ValidTime, err := time.Parse(time.RFC3339, "2030-12-31T12:59:59+00:00")
			require.NoError(t, err)

			ve, _ = b.Authorizer(loadRootPublicKey(t, v))
			verifier = &sampleVerifier{ve}
			verifier.AddResource("file1")
			verifier.SetTime(file1ValidTime)
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Authorize())

			ve, _ = b.Authorizer(loadRootPublicKey(t, v))
			verifier = &sampleVerifier{ve}
			verifier.AddResource("file1")
			verifier.SetTime(file1ValidTime.Add(1 * time.Second))
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, verifier.Authorize())

			ve, _ = b.Authorizer(loadRootPublicKey(t, v))
			verifier = &sampleVerifier{ve}
			verifier.AddResource("file2")
			verifier.SetTime(time.Now())
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, verifier.Authorize())

			otherFileValidTime, err := time.Parse(time.RFC3339, "1999-12-31T12:59:59+00:00")
			require.NoError(t, err)

			ve, _ = b.Authorizer(loadRootPublicKey(t, v))
			verifier = &sampleVerifier{ve}
			verifier.AddResource("file2")
			verifier.SetTime(otherFileValidTime)
			verifier.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, verifier.Authorize())
		})
	}
}

func TestSample14_RegexConstraint(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test14_regex_constraint.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			validFiles := []string{
				"file1.txt",
				"file1.txt.zip",
				"file9000.txt",
				"/dir/file000.txt",
				"file000.txt/dir/",
			}

			for _, validFile := range validFiles {
				v, err := b.Authorizer(loadRootPublicKey(t, v))
				require.NoError(t, err)

				verifier := &sampleVerifier{v}

				verifier.Reset()
				verifier.AddResource(validFile)
				verifier.AddPolicy(biscuit.DefaultAllowPolicy)
				require.NoError(t, verifier.Authorize())
			}

			invalidFiles := []string{
				"file1",
				"fileA.txt",
				"fileA1.txt",
				"file1.zip",
			}

			for _, invalidFile := range invalidFiles {
				v, err := b.Authorizer(loadRootPublicKey(t, v))
				require.NoError(t, err)

				verifier := &sampleVerifier{v}

				verifier.Reset()
				verifier.AddResource(invalidFile)
				verifier.AddPolicy(biscuit.DefaultAllowPolicy)
				require.Error(t, verifier.Authorize())
			}
		})
	}
}

func TestSample15_MultiQueriesChecks(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test15_multi_queries_caveats.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)

			rule1 := biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "test_must_be_present_authority",
					IDs:  []biscuit.Term{biscuit.Variable("0")},
				},
				Body: []biscuit.Predicate{
					{Name: "must_be_present", IDs: []biscuit.Term{biscuit.Variable("0")}},
				},
			}

			rule2 := biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "test_must_be_present",
					IDs:  []biscuit.Term{biscuit.Variable("0")},
				},
				Body: []biscuit.Predicate{
					{Name: "must_be_present", IDs: []biscuit.Term{biscuit.Variable("0")}},
				},
			}

			v.AddCheck(biscuit.Check{Queries: []biscuit.Rule{rule1, rule2}})
			v.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, v.Authorize())

			v.Reset()
			v.AddCheck(biscuit.Check{Queries: []biscuit.Rule{rule1}})
			v.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, v.Authorize())

			v.Reset()
			v.AddCheck(biscuit.Check{Queries: []biscuit.Rule{rule2}})
			v.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, v.Authorize())
		})
	}
}

func TestSample16_CheckHeadName(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test16_caveat_head_name.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)

			v.AddPolicy(biscuit.DefaultAllowPolicy)
			require.Error(t, v.Authorize())

			v.Reset()
			v.AddFact(biscuit.Fact{
				Predicate: biscuit.Predicate{Name: "resource", IDs: []biscuit.Term{biscuit.String("hello")}},
			})
			v.AddPolicy(biscuit.DefaultAllowPolicy)
			require.NoError(t, v.Authorize())
		})
	}
}
func TestSample17_Expressions(t *testing.T) {
	t.Run("v1", func(t *testing.T) {
		token := loadSampleToken(t, "v2", "test17_expressions.bc")

		b, err := biscuit.Unmarshal(token)
		require.NoError(t, err)

		v, err := b.Authorizer(loadRootPublicKey(t, "v2"))
		require.NoError(t, err)

		v.AddPolicy(biscuit.DefaultAllowPolicy)
		require.NoError(t, v.Authorize())
	})
}

func TestSample18_UnboundVariables(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test18_unbound_variables_in_rule.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			v, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)
			v.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: "operation",
				IDs:  []biscuit.Term{biscuit.String("write")},
			}})
			require.Error(t, v.Authorize())
		})
	}
}

func TestSample19_GeneratingAmbientFromVariables(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test19_generating_ambient_from_variables.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			t.Log(b.String())

			v, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)

			v.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
				Name: "operation",
				IDs:  []biscuit.Term{biscuit.String("write")},
			}})
			require.Error(t, v.Authorize())
		})
	}
}

func TestSample20_Sealed(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test20_sealed.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			t.Log(b.String())

			ve, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)

			v := &sampleVerifier{ve}

			v.AddOperation("red")
			v.AddResource("file1")

			require.Error(t, v.Authorize())
		})
	}
}

func TestSample21_Parsing(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test21_parsing.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			t.Log(b.String())

			v, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)

			check1, err := parser.FromStringCheck(`check if ns::fact_123("hello é\t😁")`)
			require.NoError(t, err)
			v.AddCheck(check1)

			v.AddPolicy(biscuit.DefaultAllowPolicy)

			require.NoError(t, v.Authorize())
		})
	}
}

func TestSample22_DefaultSymbols(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test22_default_symbols.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			t.Log(b.String())

			v, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)

			check1, err := parser.FromStringCheck(`check if read(0), write(1), resource(2), operation(3),
			right(4), time(5), role(6), owner(7), tenant(8), namespace(9), user(10), team(11), service(12),
			admin(13), email(14), group(15), member(16), ip_address(17), client(18), client_ip(19),
			domain(20), path(21), version(22), cluster(23), node(24), hostname(25), nonce(26), query(27)`)
			require.NoError(t, err)
			v.AddCheck(check1)

			v.AddPolicy(biscuit.DefaultAllowPolicy)

			require.NoError(t, v.Authorize())
		})
	}
}

func TestSample23_ExecutionScope(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test23_execution_scope.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			t.Log(b.String())

			v, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)

			v.AddPolicy(biscuit.DefaultAllowPolicy)

			require.Error(t, v.Authorize())

		})
	}
}

func loadSampleToken(t *testing.T, version string, path string) []byte {
	token, err := os.ReadFile(fmt.Sprintf("data/%s/%s", version, path))
	require.NoError(t, err)

	return token
}

func loadRootPublicKey(t *testing.T, version string) ed25519.PublicKey {
	pubkey, err := os.ReadFile(fmt.Sprintf("data/%s/root_key.pub", version))
	require.NoError(t, err)

	return pubkey
}
