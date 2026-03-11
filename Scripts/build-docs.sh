#!/usr/bin/env bash
# Build a static DocC documentation site for all Diem library targets.
#
# Usage:
#   bash Scripts/build-docs.sh [--base-path /your/base/path]
#
# Options:
#   --base-path PATH   URL prefix under which the site will be served (default: /)
#
# Requires:
#   • swiftly with a Swift 6.3+ development snapshot active

set -euo pipefail

TARGETS=(
  Diem
  DiemMocks
  DiemSwiftCrypto
  DiemStores
  DiemStoresInMemory
  DiemStoresGRDB
  DiemStoresKeychain
)

rm -rf ./dist
mkdir -p ./dist

echo "→ Generating docs for all targets..."
swiftly run swift package \
  --allow-writing-to-directory "./dist" \
  generate-documentation \
  $(for target in "${TARGETS[@]}"; do echo --target "$target"; done) \
  --output-path "./dist" \
  --experimental-transform-for-static-hosting-with-content \
  --enable-experimental-overloaded-symbol-presentation \
  --enable-experimental-combined-documentation\
  --enable-experimental-code-block-annotations \
  --checkout-path . \
  --source-service github \
  --source-service-base-url https://github.com/UInt8Co/diem/blob/main
