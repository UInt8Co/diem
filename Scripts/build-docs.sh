#!/usr/bin/env bash
# Build a static DocC documentation site for all Diem library targets.
#
# Requires the repository's Swift toolchain on PATH.

set -euo pipefail

TARGETS=(
  Diem
  DiemSwiftCrypto
)

# Swift 6.4's experimental HTML-content renderer crashes in FoundationXML on
# Linux. Static routing is supported there; macOS can also prerender page content.
STATIC_HOSTING=--experimental-transform-for-static-hosting-with-content
if [[ "$(uname -s)" == Linux ]]; then
  STATIC_HOSTING=--transform-for-static-hosting
fi

rm -rf ./dist
mkdir -p ./dist

echo "→ Generating docs for all targets..."
swift package \
  --allow-writing-to-directory "./dist" \
  generate-documentation \
  $(for target in "${TARGETS[@]}"; do echo --target "$target"; done) \
  --output-path "./dist" \
  "$STATIC_HOSTING" \
  --enable-experimental-overloaded-symbol-presentation \
  --enable-experimental-combined-documentation \
  --enable-experimental-code-block-annotations \
  --checkout-path . \
  --source-service github \
  --source-service-base-url https://github.com/UInt8Co/diem/blob/main
