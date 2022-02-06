package biscuit_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/biscuit-auth/biscuit-go"
)

func ExampleBiscuit() {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)
	builder := biscuit.NewBuilder(privateRoot)

	err := builder.AddAuthorityFact(biscuit.Fact{biscuit.Predicate{
		Name: "right",
		IDs: []biscuit.Term{
			biscuit.String("/a/file1.txt"),
			biscuit.String("read"),
		},
	}})
	if err != nil {
		panic(fmt.Errorf("failed to add authority facts: %v", err))
	}
	err = builder.AddAuthorityFact(biscuit.Fact{biscuit.Predicate{
		Name: "right",
		IDs: []biscuit.Term{
			biscuit.String("/a/file1.txt"),
			biscuit.String("write"),
		},
	}})
	if err != nil {
		panic(fmt.Errorf("failed to add authority facts: %v", err))
	}
	err = builder.AddAuthorityFact(biscuit.Fact{biscuit.Predicate{
		Name: "right",
		IDs: []biscuit.Term{
			biscuit.String("/a/file2.txt"),
			biscuit.String("read"),
		},
	}})
	if err != nil {
		panic(fmt.Errorf("failed to add authority facts: %v", err))
	}
	err = builder.AddAuthorityFact(biscuit.Fact{biscuit.Predicate{
		Name: "right",
		IDs: []biscuit.Term{
			biscuit.String("/a/file3.txt"),
			biscuit.String("write"),
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

	fmt.Printf("Token1 length: %d\n", len(token))

	deser, err := biscuit.Unmarshal(token)
	if err != nil {
		panic(fmt.Errorf("failed to deserialize biscuit: %v", err))
	}

	blockBuilder := deser.CreateBlock()
	blockBuilder.AddCheck(biscuit.Check{
		Queries: []biscuit.Rule{
			{
				Head: biscuit.Predicate{
					Name: "allow_read_only",
					IDs:  []biscuit.Term{biscuit.Variable("file"), biscuit.Variable("permission")},
				},
				Body: []biscuit.Predicate{
					{Name: "resource", IDs: []biscuit.Term{biscuit.Variable("file")}},
					{Name: "operation", IDs: []biscuit.Term{biscuit.Variable("permission")}},
				},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Set{biscuit.String("read")}},
						biscuit.Value{Term: biscuit.Variable("permission")},
						biscuit.BinaryContains,
					},
				},
			},
		},
	})

	b2, err := deser.Append(rng, blockBuilder.Build())
	if err != nil {
		panic(fmt.Errorf("failed to append: %v", err))
	}

	token2, err := b2.Serialize()
	if err != nil {
		panic(fmt.Errorf("failed to serialize biscuit: %v", err))
	}

	fmt.Printf("Token2 length: %d\n", len(token2))

	// Verify
	b2, err = biscuit.Unmarshal(token2)
	if err != nil {
		panic(fmt.Errorf("failed to deserialize token: %v", err))
	}

	v1, err := b2.Verify(publicRoot)
	if err != nil {
		panic(fmt.Errorf("failed to create verifier: %v", err))
	}

	v1.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "resource", IDs: []biscuit.Term{biscuit.String("/a/file1.txt")}},
	})
	v1.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "operation", IDs: []biscuit.Term{biscuit.String("read")}},
	})
	v1.AddPolicy(biscuit.Policy{Kind: biscuit.PolicyKindAllow, Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "allow_file_1"},
			Body: []biscuit.Predicate{
				{Name: "resource", IDs: []biscuit.Term{biscuit.String("/a/file1.txt")}},
			},
		},
	}})
	if err := v1.Verify(); err != nil {
		fmt.Println(v1.PrintWorld())
		fmt.Println("forbidden to read /a/file1.txt")
	} else {
		fmt.Println("allowed to read /a/file1.txt")
	}

	v1, _ = b2.Verify(publicRoot)

	v1.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "resource", IDs: []biscuit.Term{biscuit.String("/a/file1.txt")}},
	})
	v1.AddFact(biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "operation", IDs: []biscuit.Term{biscuit.String("write")}},
	})
	v1.AddPolicy(biscuit.Policy{Kind: biscuit.PolicyKindAllow, Queries: []biscuit.Rule{
		{
			Head: biscuit.Predicate{Name: "allow_file_1"},
			Body: []biscuit.Predicate{
				{Name: "resource", IDs: []biscuit.Term{biscuit.String("/a/file1.txt")}},
			},
		},
	}})

	if err := v1.Verify(); err != nil {
		fmt.Println("forbidden to write /a/file1.txt")
	} else {
		fmt.Println("allowed to write /a/file1.txt")
	}

	// Output: Token1 length: 260
	// Token2 length: 464
	// allowed to read /a/file1.txt
	// forbidden to write /a/file1.txt
}
