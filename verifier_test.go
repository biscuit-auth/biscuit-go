package biscuit

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/flynn/biscuit-go/sig"
	"github.com/stretchr/testify/require"
)

func TestGetBlockID(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)
	builder := NewBuilder(rng, root)

	// add 3 facts authority_0_fact_{0,1,2} in authority block
	for i := 0; i < 3; i++ {
		require.NoError(t, builder.AddAuthorityFact(Fact{Predicate: Predicate{
			Name: fmt.Sprintf("authority_0_fact_%d", i),
			IDs:  []Atom{Integer(i)},
		}}))
	}

	b, err := builder.Build()
	require.NoError(t, err)
	// add 2 extra blocks each containing 3 facts block_{0,1}_fact_{0,1,2}
	for i := 0; i < 2; i++ {
		blockBuilder := b.CreateBlock()
		for j := 0; j < 3; j++ {
			blockBuilder.AddFact(Fact{Predicate: Predicate{
				Name: fmt.Sprintf("block_%d_fact_%d", i, j),
				IDs:  []Atom{Symbol("block"), Integer(i), Integer(j)},
			}})
		}
		b, err = b.Append(rng, sig.GenerateKeypair(rng), blockBuilder.Build())
		require.NoError(t, err)
	}

	v, err := b.Verify(root.Public())
	require.NoError(t, err)

	idx, err := v.GetBlockID(Fact{Predicate{
		Name: "authority_0_fact_0",
		IDs:  []Atom{Symbol("authority"), Integer(0)},
	}})
	require.NoError(t, err)
	require.Equal(t, 0, idx)
	idx, err = v.GetBlockID(Fact{Predicate{
		Name: "authority_0_fact_2",
		IDs:  []Atom{Symbol("authority"), Integer(2)},
	}})
	require.NoError(t, err)
	require.Equal(t, 0, idx)

	idx, err = v.GetBlockID(Fact{Predicate{
		Name: "block_0_fact_2",
		IDs:  []Atom{Symbol("block"), Integer(0), Integer(2)},
	}})
	require.NoError(t, err)
	require.Equal(t, 1, idx)
	idx, err = v.GetBlockID(Fact{Predicate{
		Name: "block_1_fact_1",
		IDs:  []Atom{Symbol("block"), Integer(1), Integer(1)},
	}})
	require.NoError(t, err)
	require.Equal(t, 2, idx)

	_, err = v.GetBlockID(Fact{Predicate{
		Name: "block_1_fact_3",
		IDs:  []Atom{Symbol("block"), Integer(1), Integer(3)},
	}})
	require.Error(t, err)
	_, err = v.GetBlockID(Fact{Predicate{
		Name: "block_2_fact_1",
		IDs:  []Atom{Symbol("block"), Integer(2), Integer(1)},
	}})
	require.Error(t, err)
	_, err = v.GetBlockID(Fact{Predicate{
		Name: "block_1_fact_1",
		IDs:  []Atom{Integer(1), Integer(1)},
	}})
	require.Error(t, err)
}
