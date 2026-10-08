#!/usr/bin/env bash

# Buf tooling expects a fully qualified path to the plugins directory.
BUF="go run github.com/bufbuild/buf/cmd/buf@v1.50.0"

# Installs protoc plugins required by our buf config.
BUF_PLUGINS_DIR="$(pwd)/.buf-plugins"
mkdir -p "$BUF_PLUGINS_DIR"
GOBIN="$BUF_PLUGINS_DIR" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.5

# Generate pb code from the biscuit spec. Pinned to the commit after v3.3 that
# adds OpBinary.TryOr, which the v3.3 samples use.
PATH="${BUF_PLUGINS_DIR}:$PATH" $BUF generate \
    --template buf.gen.yaml \
    --debug \
    https://github.com/eclipse-biscuit/biscuit.git#ref=b3d3fe2
