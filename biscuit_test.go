package biscuit

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/flynn/biscuit-go/sig"
	"github.com/stretchr/testify/require"
)

func TestBiscuit(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)

	builder := NewBuilder(rng, root)

	builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Atom{Symbol("authority"), String("/a/file1"), Symbol("read")}},
	})
	builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Atom{Symbol("authority"), String("/a/file1"), Symbol("write")}},
	})
	builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Atom{Symbol("authority"), String("/a/file2"), Symbol("read")}},
	})

	b1, err := builder.Build()
	require.NoError(t, err)

	b1ser, err := b1.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, b1ser)

	b1deser, err := Unmarshal(b1ser)
	require.NoError(t, err)

	block2 := b1deser.CreateBlock()
	block2.AddCaveat(Caveat{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat", IDs: []Atom{Variable(0)}},
				Body: []Predicate{
					{Name: "resource", IDs: []Atom{Symbol("ambient"), Variable(0)}},
					{Name: "operation", IDs: []Atom{Symbol("ambient"), Symbol("read")}},
					{Name: "right", IDs: []Atom{Symbol("authority"), Variable(0), Symbol("read")}},
				},
			},
		},
	})

	keypair2 := sig.GenerateKeypair(rng)
	b2, err := b1deser.Append(rng, keypair2, block2.Build())
	require.NoError(t, err)

	b2ser, err := b2.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, b2ser)

	b2deser, err := Unmarshal(b2ser)
	require.NoError(t, err)

	block3 := b2deser.CreateBlock()
	block3.AddCaveat(Caveat{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat2", IDs: []Atom{String("/a/file1")}},
				Body: []Predicate{
					{Name: "resource", IDs: []Atom{Symbol("ambient"), String("/a/file1")}},
				},
			},
		},
	})

	keypair3 := sig.GenerateKeypair(rng)
	b3, err := b2deser.Append(rng, keypair3, block3.Build())
	require.NoError(t, err)

	b3ser, err := b3.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, b3ser)

	b3deser, err := Unmarshal(b3ser)
	require.NoError(t, err)

	v3, err := b3deser.Verify(root.Public())
	require.NoError(t, err)

	v3.AddOperation("read")
	v3.AddResource("/a/file1")
	require.NoError(t, v3.Verify())

	v3.Reset()
	v3.AddOperation("read")
	v3.AddResource("/a/file2")
	require.Error(t, v3.Verify())

	v3.Reset()
	v3.AddOperation("write")
	v3.AddResource("/a/file1")
	require.Error(t, v3.Verify())
}

func TestBiscuitRules(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)

	builder := NewBuilder(rng, root)

	builder.AddAuthorityRule(Rule{
		Head: Predicate{Name: "right", IDs: []Atom{Variable(1), Symbol("read")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Atom{Symbol("ambient"), Variable(1)}},
			{Name: "owner", IDs: []Atom{Symbol("ambient"), Variable(0), Variable(1)}},
		},
	})
	builder.AddAuthorityRule(Rule{
		Head: Predicate{Name: "right", IDs: []Atom{Variable(1), Symbol("write")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Atom{Symbol("ambient"), Variable(1)}},
			{Name: "owner", IDs: []Atom{Symbol("ambient"), Variable(0), Variable(1)}},
		},
	})

	b1, err := builder.Build()
	require.NoError(t, err)

	block := b1.CreateBlock()
	block.AddCaveat(Caveat{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat1", IDs: []Atom{Variable(0), Variable(1)}},
				Body: []Predicate{
					{Name: "right", IDs: []Atom{Symbol("authority"), Variable(0), Variable(1)}},
					{Name: "resource", IDs: []Atom{Symbol("ambient"), Variable(0)}},
					{Name: "operation", IDs: []Atom{Symbol("ambient"), Variable(1)}},
				},
			},
			{
				Head: Predicate{Name: "caveat2", IDs: []Atom{Variable(0)}},
				Body: []Predicate{
					{Name: "resource", IDs: []Atom{Symbol("ambient"), Variable(0)}},
					{Name: "owner", IDs: []Atom{Symbol("ambient"), Symbol("alice"), Variable(0)}},
				},
			},
		},
	})

	b2, err := b1.Append(rng, sig.GenerateKeypair(rng), block.Build())
	require.NoError(t, err)

	v, err := b2.Verify(root.Public())
	require.NoError(t, err)

	v.AddOperation("write")
	v.AddResource("file1")
	v.AddFact(Fact{
		Predicate: Predicate{
			Name: "owner",
			IDs: []Atom{
				Symbol("ambient"),
				Symbol("alice"),
				String("file1"),
			},
		},
	})

	fmt.Println(v.PrintWorld())
	fmt.Println(b2.String())

	require.NoError(t, v.Verify())
	t.Fail()
}
