package biscuit

import (
	"crypto/rand"
	"testing"

	"github.com/flynn/biscuit-go/sig"
	"github.com/stretchr/testify/require"
)

func TestVerifierDefaultPolicy(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)

	builder := NewBuilder(root)
	err := builder.AddAuthorityFact(Fact{Predicate{
		Name: "right",
		IDs: []Term{
			Symbol("authority"),
			String("/a/file1.txt"),
			Symbol("read"),
		},
	}})
	require.NoError(t, err)

	b, err := builder.Build()
	require.NoError(t, err)

	v, err := b.Verify(root.Public())
	require.NoError(t, err)

	v.AddPolicy(DefaultDenyPolicy)
	err = v.Verify()
	require.Equal(t, err, ErrPolicyDenied)

	v.Reset()
	v.AddPolicy(DefaultAllowPolicy)
	require.NoError(t, v.Verify())
}

func TestVerifierPolicies(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)

	builder := NewBuilder(root)
	err := builder.AddAuthorityRule(Rule{
		Head: Predicate{Name: "right", IDs: []Term{SymbolAuthority, Variable("file"), Variable("operation")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{Symbol("ambient"), Variable("file")}},
			{Name: "operation", IDs: []Term{Symbol("ambient"), Variable("operation")}},
		},
	})
	require.NoError(t, err)

	b, err := builder.Build()
	require.NoError(t, err)

	v, err := b.Verify(root.Public())
	require.NoError(t, err)

	policy := Policy{Kind: PolicyKindAllow, Queries: []Rule{
		{
			Head: Predicate{Name: "allow_read"},
			Body: []Predicate{
				{Name: "right", IDs: []Term{SymbolAuthority, Variable("file"), Variable("operation")}},
			},
			Expressions: []Expression{
				{
					Value{Term: Variable("operation")},
					Value{Term: String("read")},
					BinaryEqual,
				},
			},
		},
	}}

	v.AddPolicy(policy)
	v.AddFact(Fact{Predicate: Predicate{
		Name: "operation",
		IDs:  []Term{Symbol("ambient"), String("read")},
	}})
	v.AddFact(Fact{Predicate: Predicate{
		Name: "resource",
		IDs:  []Term{Symbol("ambient"), String("some_file.txt")},
	}})

	require.NoError(t, v.Verify())

	v.Reset()
	v.AddPolicy(policy)
	v.AddFact(Fact{Predicate: Predicate{
		Name: "operation",
		IDs:  []Term{Symbol("ambient"), String("write")},
	}})
	v.AddFact(Fact{Predicate: Predicate{
		Name: "resource",
		IDs:  []Term{Symbol("ambient"), String("some_file.txt")},
	}})
	require.Equal(t, v.Verify(), ErrNoMatchingPolicy)
}
