package biscuit_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
)

func ExampleBiscuit() {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)
	builder := biscuit.NewBuilder(privateRoot)

	fact1, err := parser.FromStringFact(`right("/a/file1.txt", "read")`)
	if err != nil {
		panic(fmt.Errorf("failed to parse authority facts: %v", err))
	}
	err = builder.AddAuthorityFact(fact1)
	if err != nil {
		panic(fmt.Errorf("failed to add authority facts: %v", err))
	}

	fact2, err := parser.FromStringFact(`right("/a/file1.txt", "write")`)
	if err != nil {
		panic(fmt.Errorf("failed to parse authority facts: %v", err))
	}
	err = builder.AddAuthorityFact(fact2)
	if err != nil {
		panic(fmt.Errorf("failed to add authority facts: %v", err))
	}

	fact3, err := parser.FromStringFact(`right("/a/file2.txt", "read")`)
	if err != nil {
		panic(fmt.Errorf("failed to parse authority facts: %v", err))
	}
	err = builder.AddAuthorityFact(fact3)
	if err != nil {
		panic(fmt.Errorf("failed to add authority facts: %v", err))
	}

	fact4, err := parser.FromStringFact(`right("/a/file3.txt", "write")`)
	if err != nil {
		panic(fmt.Errorf("failed to parse authority facts: %v", err))
	}
	err = builder.AddAuthorityFact(fact4)
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

	check, err := parser.FromStringCheck(`check if resource($file), operation($permission), ["read"].contains($permission)`)
	if err != nil {
		panic(fmt.Errorf("failed to parse check: %v", err))
	}
	err = blockBuilder.AddCheck(check)
	if err != nil {
		panic(fmt.Errorf("failed to add block check: %v", err))
	}

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

	v1, err := b2.Authorizer(publicRoot)
	if err != nil {
		panic(fmt.Errorf("failed to create verifier: %v", err))
	}

	vfact1, err := parser.FromStringFact(`resource("/a/file1.txt")`)
	if err != nil {
		panic(fmt.Errorf("failed to parse verifier fact: %v", err))
	}
	v1.AddFact(vfact1)

	vfact2, err := parser.FromStringFact(`operation("read")`)
	if err != nil {
		panic(fmt.Errorf("failed to parse verifier fact: %v", err))
	}
	v1.AddFact(vfact2)

	policy, err := parser.FromStringPolicy(`allow if resource("/a/file1.txt")`)
	if err != nil {
		panic(fmt.Errorf("failed to parse verifier policy: %v", err))
	}
	v1.AddPolicy(policy)

	if err := v1.Authorize(); err != nil {
		fmt.Println(v1.PrintWorld())
		fmt.Println("forbidden to read /a/file1.txt")
	} else {
		//fmt.Println(v1.PrintWorld())

		fmt.Println("allowed to read /a/file1.txt")
	}

	v1, _ = b2.Authorizer(publicRoot)

	vfact1, err = parser.FromStringFact(`resource("/a/file1.txt")`)
	if err != nil {
		panic(fmt.Errorf("failed to parse verifier fact: %v", err))
	}
	v1.AddFact(vfact1)

	vfact2, err = parser.FromStringFact(`operation("write")`)
	if err != nil {
		panic(fmt.Errorf("failed to parse verifier fact: %v", err))
	}
	v1.AddFact(vfact2)

	policy, err = parser.FromStringPolicy(`allow if resource("/a/file1.txt")`)
	if err != nil {
		panic(fmt.Errorf("failed to parse verifier policy: %v", err))
	}
	v1.AddPolicy(policy)

	if err := v1.Authorize(); err != nil {
		fmt.Println("forbidden to write /a/file1.txt")
	} else {
		fmt.Println("allowed to write /a/file1.txt")
	}

	// Output: Token1 length: 251
	// Token2 length: 433
	// allowed to read /a/file1.txt
	// forbidden to write /a/file1.txt
}
