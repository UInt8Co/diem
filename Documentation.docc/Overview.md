# Diem

@Metadata {
  @TechnologyRoot
}

Portable identities built from keys, signed messages, device-certified profiles and proofs.

Browsers run the same rules from WebAssembly: the `Web/` package builds the standalone
`diem.wasm` runtime and the `DiemWeb` library that applications link into their own
runtime, with WebCrypto keys, profile hosting, recovery words and QR device linking.
`Web/README.md` is its contract. `Android/` holds Keystore device keys.

## Topics

- `/Diem`
- `/DiemSwiftCrypto`
- `/DiemProfileHostingClient`
- `/DiemProfileHosting`
- `/DiemTesting`
