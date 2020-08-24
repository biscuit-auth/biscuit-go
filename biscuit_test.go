package biscuit

import (
	"crypto/rand"
	"testing"

	"github.com/flynn/biscuit-go/datalog"
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
		},
	})
	block.AddCaveat(Caveat{
		Queries: []Rule{
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

	require.NoError(t, v.Verify())
}

func TestCheckRootKey(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)

	builder := NewBuilder(rng, root)

	b, err := builder.Build()
	require.NoError(t, err)

	require.NoError(t, b.checkRootKey(root.Public()))

	notRoot := sig.GenerateKeypair(rng)
	require.Equal(t, ErrUnknownPublicKey, b.checkRootKey(notRoot.Public()))

	b.container.Keys = [][]byte{}
	require.Equal(t, ErrEmptyKeys, b.checkRootKey(notRoot.Public()))
}

func TestGenerateWorld(t *testing.T) {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)

	build := NewBuilder(rng, root)

	authorityFact1 := Fact{Predicate: Predicate{Name: "fact1", IDs: []Atom{Symbol("authority"), String("file1")}}}
	authorityFact2 := Fact{Predicate: Predicate{Name: "fact2", IDs: []Atom{Symbol("authority"), String("file2")}}}

	authorityRule1 := Rule{
		Head: Predicate{Name: "right", IDs: []Atom{Symbol("authority"), Variable(1), Symbol("read")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Atom{Symbol("ambient"), Variable(1)}},
			{Name: "owner", IDs: []Atom{Symbol("ambient"), Variable(0), Variable(1)}},
		},
	}
	authorityRule2 := Rule{
		Head: Predicate{Name: "right", IDs: []Atom{Symbol("authority"), Variable(1), Symbol("write")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Atom{Symbol("ambient"), Variable(1)}},
			{Name: "owner", IDs: []Atom{Symbol("ambient"), Variable(0), Variable(1)}},
		},
	}

	build.AddAuthorityFact(authorityFact1)
	build.AddAuthorityFact(authorityFact2)
	build.AddAuthorityRule(authorityRule1)
	build.AddAuthorityRule(authorityRule2)

	b, err := build.Build()
	require.NoError(t, err)

	symbolTable := (build.(*builder)).symbols
	world, err := b.generateWorld(DefaultSymbolTable)
	require.NoError(t, err)

	expectedWorld := datalog.NewWorld()
	expectedWorld.AddFact(authorityFact1.convert(symbolTable))
	expectedWorld.AddFact(authorityFact2.convert(symbolTable))
	expectedWorld.AddRule(authorityRule1.convert(symbolTable))
	expectedWorld.AddRule(authorityRule2.convert(symbolTable))
	require.Equal(t, expectedWorld, world)

	blockBuild := b.CreateBlock()
	blockRule := Rule{
		Head: Predicate{Name: "blockRule", IDs: []Atom{Variable(1)}},
		Body: []Predicate{
			{Name: "resource", IDs: []Atom{Symbol("ambient"), Variable(1)}},
			{Name: "owner", IDs: []Atom{Symbol("ambient"), Symbol("alice"), Variable(1)}},
		},
	}
	blockBuild.AddRule(blockRule)

	blockFact := Fact{Predicate{Name: "resource", IDs: []Atom{String("file1")}}}
	blockBuild.AddFact(blockFact)

	b2, err := b.Append(rng, sig.GenerateKeypair(rng), blockBuild.Build())
	require.NoError(t, err)

	allSymbols := append(*symbolTable, *(blockBuild.(*blockBuilder)).symbols...)
	world, err = b2.generateWorld(&allSymbols)
	require.NoError(t, err)

	expectedWorld = datalog.NewWorld()
	expectedWorld.AddFact(authorityFact1.convert(&allSymbols))
	expectedWorld.AddFact(authorityFact2.convert(&allSymbols))
	expectedWorld.AddFact(blockFact.convert(&allSymbols))
	expectedWorld.AddRule(authorityRule1.convert(&allSymbols))
	expectedWorld.AddRule(authorityRule2.convert(&allSymbols))
	expectedWorld.AddRule(blockRule.convert(&allSymbols))
	require.Equal(t, expectedWorld, world)

}

func TestGenerateWorldErrors(t *testing.T) {
	testCases := []struct {
		Desc       string
		Symbols    *datalog.SymbolTable
		Facts      []Fact
		BlockFacts []Fact
		BlockRules []Rule
	}{
		{
			Desc:    "missing authority symbol",
			Symbols: &datalog.SymbolTable{},
		},
		{
			Desc:    "missing ambient symbol",
			Symbols: &datalog.SymbolTable{"authority"},
		},
		{
			Desc:    "invalid ambient authority fact",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			Facts: []Fact{
				{Predicate: Predicate{Name: "test", IDs: []Atom{Symbol("ambient"), Variable(0)}}},
			},
		},
		{
			Desc:    "empty authority fact",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			Facts: []Fact{
				{Predicate: Predicate{Name: "test", IDs: []Atom{}}},
			},
		},
		{
			Desc:    "invalid block fact authority",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			BlockFacts: []Fact{
				{Predicate: Predicate{Name: "test", IDs: []Atom{Symbol("authority"), Variable(0)}}},
			},
		},
		{
			Desc:    "invalid block fact ambient",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			BlockFacts: []Fact{
				{Predicate: Predicate{Name: "test", IDs: []Atom{Symbol("ambient"), Variable(0)}}},
			},
		},
		{
			Desc:    "invalid block fact empty",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			BlockFacts: []Fact{
				{Predicate: Predicate{Name: "test", IDs: []Atom{}}},
			},
		},
		{
			Desc:    "invalid block rule authority",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			BlockRules: []Rule{
				{Head: Predicate{Name: "test", IDs: []Atom{Symbol("authority")}}},
			},
		},
		{
			Desc:    "invalid block rule ambient",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			BlockRules: []Rule{
				{Head: Predicate{Name: "test", IDs: []Atom{Symbol("ambient")}}},
			},
		},
		{
			Desc:    "invalid block rule empty",
			Symbols: &datalog.SymbolTable{"authority", "ambient"},
			BlockRules: []Rule{
				{Head: Predicate{Name: "test", IDs: []Atom{}}},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			rng := rand.Reader
			root := sig.GenerateKeypair(rng)

			builder := NewBuilder(rng, root)
			b, err := builder.Build()
			require.NoError(t, err)

			facts := make(datalog.FactSet, 0, len(testCase.Facts))
			for _, f := range testCase.Facts {
				facts = append(facts, f.convert(testCase.Symbols))
			}
			b.authority.facts = &facts

			blockFacts := make(datalog.FactSet, 0, len(testCase.BlockFacts))
			for _, f := range testCase.BlockFacts {
				blockFacts = append(blockFacts, f.convert(testCase.Symbols))
			}

			blockRules := make([]datalog.Rule, 0, len(testCase.BlockRules))
			for _, r := range testCase.BlockRules {
				blockRules = append(blockRules, r.convert(testCase.Symbols))
			}

			b.blocks = []*Block{{
				facts: &blockFacts,
				rules: blockRules,
			}}

			_, err = b.generateWorld(testCase.Symbols)
			require.Error(t, err)
		})
	}
}

func TestAppendErrors(t *testing.T) {
	rng := rand.Reader
	builder := NewBuilder(rng, sig.GenerateKeypair(rng))

	t.Run("symbols overlap", func(t *testing.T) {
		b, err := builder.Build()
		require.NoError(t, err)

		_, err = b.Append(rng, sig.GenerateKeypair(rng), &Block{
			symbols: &datalog.SymbolTable{"authority"},
		})
		require.Equal(t, ErrSymbolTableOverlap, err)
	})

	t.Run("invalid block index", func(t *testing.T) {
		b, err := builder.Build()
		require.NoError(t, err)

		_, err = b.Append(rng, sig.GenerateKeypair(rng), &Block{
			symbols: &datalog.SymbolTable{},
			index:   2,
		})
		require.Equal(t, ErrInvalidBlockIndex, err)
	})

	t.Run("biscuit is sealed", func(t *testing.T) {
		b, err := builder.Build()
		require.NoError(t, err)
		_, err = b.Append(rng, sig.GenerateKeypair(rng), &Block{
			symbols: &datalog.SymbolTable{},
			facts:   &datalog.FactSet{},
			index:   1,
		})
		require.NoError(t, err)

		b.container = nil
		_, err = b.Append(rng, sig.GenerateKeypair(rng), &Block{
			symbols: &datalog.SymbolTable{},
			index:   1,
		})
		require.Error(t, err)
	})
}
