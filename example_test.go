package biscuit_test

import (
	"crypto/rand"
	"fmt"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/sig"
)

func ExampleBiscuit() {
	rng := rand.Reader
	root := sig.GenerateKeypair(rng)
	// publicKey := root.Public()

	builder := biscuit.NewBuilder(rng, root)

	// `right(#authority, "/a/file1.txt", #read)`,
	err := builder.AddAuthorityFact(&biscuit.Fact{biscuit.Predicate{
		Name: "right",
		IDs: []biscuit.Atom{
			biscuit.Symbol("authority"),
			biscuit.String("/a/file1.txt"),
			biscuit.Symbol("read"),
		},
	}})
	if err != nil {
		panic(fmt.Errorf("failed to add authority facts: %v", err))
	}
	err = builder.AddAuthorityFact(&biscuit.Fact{biscuit.Predicate{
		Name: "right",
		IDs: []biscuit.Atom{
			biscuit.Symbol("authority"),
			biscuit.String("/a/file1.txt"),
			biscuit.Symbol("write"),
		},
	}})
	if err != nil {
		panic(fmt.Errorf("failed to add authority facts: %v", err))
	}
	err = builder.AddAuthorityFact(&biscuit.Fact{biscuit.Predicate{
		Name: "right",
		IDs: []biscuit.Atom{
			biscuit.Symbol("authority"),
			biscuit.String("/a/file2.txt"),
			biscuit.Symbol("read"),
		},
	}})
	if err != nil {
		panic(fmt.Errorf("failed to add authority facts: %v", err))
	}
	err = builder.AddAuthorityFact(&biscuit.Fact{biscuit.Predicate{
		Name: "right",
		IDs: []biscuit.Atom{
			biscuit.Symbol("authority"),
			biscuit.String("/a/file3.txt"),
			biscuit.Symbol("write"),
		},
	}})
	if err != nil {
		panic(fmt.Errorf("failed to add authority facts: %v", err))
	}

	b, err := builder.Build()
	if err != nil {
		panic(fmt.Errorf("failed to build biscuit: %v", err))
	}

	token, err := b.Serialize()
	if err != nil {
		panic(fmt.Errorf("failed to serialize biscuit: %v", err))
	}

	fmt.Printf("Token length: %d\n", len(token))
	// Output: Token length: 266
}
