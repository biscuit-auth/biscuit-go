package pb

//go:generate ../build/protoc/bin/protoc --plugin=../build/bin/protoc-gen-go --go_out=. --proto_path ../build/protoc/include --proto_path . biscuit.proto
