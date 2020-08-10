#!/bin/bash

set -eo pipefail

protoc_version="3.12.3"
protoc_shasum="90257aed22e983a6772fb5af259a14d8f78deac0814a7df76a741975ffeea1c0"

protos_version="1_3_1"
protos_shasum="9584b7ac21de5b31832faf827f898671cdcb034bd557a36ea3e7fc07e6571dcb"

gobin_version="0.0.14"
gobin_shasum="5bc800e8be7eaefcb86780786c38b75243082685a17ceea3c2235e06b8259151"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "${ROOT}/build/bin"

tmpdir=$(mktemp --directory)
trap "rm -rf ${tmpdir}" EXIT

# install protobuf compiler
curl -sL https://github.com/google/protobuf/releases/download/v${protoc_version}/protoc-${protoc_version}-linux-x86_64.zip > "${tmpdir}/protoc.zip"
echo "${protoc_shasum}  ${tmpdir}/protoc.zip" | shasum -c - || (shasum -a 256 "${tmpdir}/protoc.zip" && exit 1)
unzip -d "${tmpdir}/protoc" "${tmpdir}/protoc.zip"
rm -rf "${ROOT}/build/protoc"
mv "${tmpdir}/protoc" "${ROOT}/build"

# install googleapis common protos
curl -fSLo ${tmpdir}/common-protos.tar.gz "https://github.com/googleapis/googleapis/archive/common-protos-${protos_version}.tar.gz"
echo "${protos_shasum}  ${tmpdir}/common-protos.tar.gz" | shasum -c - || (shasum -a 256 "${tmpdir}/common-protos.tar.gz" && exit 1)
tar xzf ${tmpdir}/common-protos.tar.gz -C "${ROOT}/build/protoc" --strip-components=1

gobin_dest="${ROOT}/build/bin/gobin"
curl -sLo "${gobin_dest}" https://github.com/myitcv/gobin/releases/download/v${gobin_version}/linux-amd64
echo "${gobin_shasum}  ${gobin_dest}" | shasum -c - || (shasum -a 256 "${gobin_dest}" && exit 1)
chmod +x "${gobin_dest}"

cd "${ROOT}"
GOBIN="${ROOT}/build/bin" "${gobin_dest}" -mod=readonly google.golang.org/protobuf/cmd/protoc-gen-go
