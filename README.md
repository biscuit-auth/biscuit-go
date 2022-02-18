
# biscuit-go

biscuit-go is an implementation of [Biscuit](https://github.com/biscuit-auth/biscuit) in Go. It aims to be fully compatible with other existing implementations, so that tokens issued by, for example, the Rust version, could be validated by this library and vice versa.

## Documentation and specifications

- [biscuit website](https://www.biscuitsec.org) for documentation and examples
- [biscuit specification](https://github.com/biscuit-auth/biscuit)
- [biscuit-rust](https://github.com/biscuit-auth/biscuit-rust) for some more technical details.

## Usage

#### Create a biscuit
```go
rng := rand.Reader
publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)
builder := biscuit.NewBuilder(privateRoot)

fact1, err := parser.FromStringFact(`right("/a/file1.txt", "read")`)
if err != nil {
    panic(fmt.Errorf("failed to parse authority facts: %v", err))
}

err := builder.AddAuthorityFact(fact1)
if err != nil {
    panic(fmt.Errorf("failed to add authority facts: %v", err))
}

// ... add more authority facts, rules, caveats...

b, err := builder.Build()
if err != nil {
    panic(fmt.Errorf("failed to build biscuit: %v", err))
}
token, err := b.Serialize()
if err != nil {
    panic(fmt.Errorf("failed to serialize biscuit: %v", err))
}

// token is now a []byte, ready to be shared
```

#### Attenuate a biscuit
```go
b, err = biscuit.Unmarshal(token)
if err != nil {
    panic(fmt.Errorf("failed to deserialize biscuit: %v", err))
}

// Attenuate the biscuit by appending a new block to it
blockBuilder := b.CreateBlock()
blockBuilder.AddFact(biscuit.Fact{/* ... */})

// ... add more facts, rules, caveats...

attenuatedBiscuit, err := b.Append(rng, blockBuilder.Build())
if err != nil {
    panic(fmt.Errorf("failed to append: %v", err))
}
attenuatedToken, err := b.Serialize()
if err != nil {
    panic(fmt.Errorf("failed to serialize biscuit: %v", err))
}

// token is now a []byte attenuation of the original token, and ready to be shared
```

#### Verify a biscuit

```go
b, err := biscuit.Unmarshal(token)
if err != nil {
    panic(fmt.Errorf("failed to deserialize token: %v", err))
}

authorizer, err := b.Authorizer(publicRoot)
if err != nil {
    panic(fmt.Errorf("failed to verify token and create authorizer: %v", err))
}

fact1, err := parser.FromStringFact(`resource("/a/file1.txt")`)
if err != nil {
    panic(fmt.Errorf("failed to parse authority facts: %v", err))
}

auhorizer.AddFact(fact1)

// ... add more ambient facts, rules, caveats...

authorizer.AddPolicy(biscuit.DefaultAllowPolicy)

if err := authorizer.Authorize(); err != nil {
    fmt.Printf("failed authorizing token: %v\n", err)
} else {
    fmt.Println("success authorizing token")
}
```

### Using biscuit-go grammar

To ease adding facts, rules, or caveats, a simple grammar and a parser are available, allowing to declare biscuit elements as plain strings. See [GRAMMAR reference](./parser/GRAMMAR.md) for the complete syntax.

```go
p := parser.New()
b.AddFact(p.Must().Fact(`resource("/a/file1.txt")`))
b.AddRule(p.Must().Rule(`
    can_read($file) 
        <- resource($file)
        $file.starts_with("/a/")
`))
```

## Examples

- [example_test.go](./example_test.go) for a simple use case
- [experiments folder](./experiments) for more advanced or specific use cases examples.

## License

Licensed under [Apache License, Version 2.0](./LICENSE).
