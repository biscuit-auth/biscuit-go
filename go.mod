module github.com/eclipse-biscuit/biscuit-go/v2

go 1.23

require (
	github.com/alecthomas/participle/v2 v2.1.4
	github.com/stretchr/testify v1.12.1
	go.uber.org/goleak v1.3.0
	google.golang.org/protobuf v1.36.12
)

require go.yaml.in/yaml/v3 v3.0.5 // indirect

// Biscuit.Authorizer silently ignores its options, see ./CHANGELOG.md
retract v2.2.1
