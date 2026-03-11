#!/usr/bin/env bash
# Build a static DocC documentation site for all Diem library targets.
#
# Output: dist/
#   dist/index.html          — landing page with links to each target
#   dist/<Target>/           — static DocC site for that target
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

BASE_PATH="/"
while [[ $# -gt 0 ]]; do
  case $1 in
    --base-path)
      BASE_PATH="$2"
      shift 2
      ;;
    --base-path=*)
      BASE_PATH="${1#*=}"
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# Strip trailing slash for consistent concatenation.
BASE_PATH="${BASE_PATH%/}"

TARGETS=(
  Diem
  DiemMocks
  DiemSwiftCrypto
  DiemStores
  DiemStoresInMemory
  DiemStoresGRDB
  DiemStoresKeychain
)

rm -rf dist
mkdir -p dist

for target in "${TARGETS[@]}"; do
  echo "→ Generating docs for $target..."
  swiftly run swift package generate-documentation \
    --target "$target" \
    --output-path "dist/$target" \
    --transform-for-static-hosting \
    --hosting-base-path "${BASE_PATH}/${target}"
done

# Generate a minimal landing page that links to each target's docs.
INDEX="dist/index.html"
cat > "$INDEX" << HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Diem Documentation</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           max-width: 640px; margin: 4rem auto; padding: 0 1rem; color: #1d1d1f; }
    h1   { font-size: 2rem; font-weight: 700; margin-bottom: 0.25rem; }
    p    { color: #6e6e73; margin-top: 0; }
    ul   { list-style: none; padding: 0; }
    li   { border-top: 1px solid #d2d2d7; padding: 0.75rem 0; }
    a    { font-weight: 500; color: #0066cc; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <h1>Diem</h1>
  <p>Decent Identity &amp; Encryption Mechanism — API documentation</p>
  <ul>
HTML

for target in "${TARGETS[@]}"; do
  echo "    <li><a href=\"${BASE_PATH}/${target}/documentation/${target,,}\">${target}</a></li>" >> "$INDEX"
done

cat >> "$INDEX" << HTML
  </ul>
</body>
</html>
HTML

echo "✓ Documentation built in dist/"
