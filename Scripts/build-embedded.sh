#!/usr/bin/env bash
# Build the Foundation-free Diem targets in Swift Embedded mode targeting WASM.
#
# Requires:
#   • Swift 6.3+ development snapshot on PATH (e.g. via swift-actions/setup-swift or swiftly)
#   • The wasm32-unknown-none-wasm Swift SDK installed:
#       swift sdk install <url>
#     See: https://www.swift.org/documentation/embedded/

set -euo pipefail

SDK="wasm32-unknown-none-wasm"

EMBEDDED_TARGETS=(
  "Diem"
  "DiemMocks"
  "DiemStores"
  "DiemStoresInMemory"
)

# Extra Swift compiler flags for Embedded mode.
EXTRA=(
  -Xswiftc -enable-experimental-feature -Xswiftc Embedded
  -Xswiftc -Xfrontend -Xswiftc -disable-reflection-metadata
)

# Verify the SDK is installed before attempting any builds.
if ! swift sdk list 2>/dev/null | grep -qF "$SDK"; then
  echo "error: Swift SDK '$SDK' is not installed." >&2
  echo "  Install it with: swift sdk install <wasm-sdk-url>" >&2
  echo "  See: https://www.swift.org/documentation/embedded/" >&2
  exit 1
fi

for target in "${EMBEDDED_TARGETS[@]}"; do
  echo "→ $target (Embedded WASM)…"
  swift build \
    --swift-sdk "$SDK" \
    --target "$target" \
    -c release \
    "${EXTRA[@]}"
done

echo "✓ All embedded targets built successfully."
