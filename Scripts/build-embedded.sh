#!/usr/bin/env bash
# Compile the Foundation-free CBOR and key types for freestanding WebAssembly.
# The selected Swift toolchain ships the Embedded standard-library modules; no hosted WASM SDK or
# platform crypto/storage package is needed for this target.
set -euo pipefail
cd "$(dirname "$0")/.."
compiler="${SWIFTC:-swiftc}"
output=".build/embedded"
mkdir -p "$output"
"$compiler" -target wasm32-unknown-none-wasm \
  -enable-experimental-feature Embedded -wmo -Osize -parse-as-library \
  -module-name DiemPortable -package-name diem \
  -emit-object -emit-module -emit-module-path "$output/DiemPortable.swiftmodule" \
  Sources/DiemPortable/*.swift -o "$output/DiemPortable.o"
echo "DiemPortable compiled for Embedded WebAssembly."
