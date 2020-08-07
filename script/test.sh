#!/usr/bin/env bash

set -uexo pipefail

main() {
    go test -race -v ./...
}

main $@

