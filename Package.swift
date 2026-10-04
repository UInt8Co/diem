// swift-tools-version: 6.4
import PackageDescription

let package = Package(
  name: "Diem",
  platforms: [
    .macOS(.v15),
    .iOS(.v18),
    .tvOS(.v18),
    .watchOS(.v11),
    .visionOS(.v2),
  ],
  products: [
    // Foundation-free CBOR, keys, signed messages, identities, profiles and proofs.
    .library(name: "Diem", targets: ["Diem"]),
    // A CryptoBackend on Swift Crypto, with Secure Enclave keys on Apple platforms.
    .library(name: "DiemSwiftCrypto", targets: ["DiemSwiftCrypto"]),
    // Writes cross-language wire vectors.
    .executable(name: "diem-vectors", targets: ["DiemVectors"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-crypto.git", from: "5.0.0"),
    .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.5.0"),
  ],
  targets: [
    .target(name: "Diem"),
    .target(
      name: "DiemSwiftCrypto",
      dependencies: ["Diem", .product(name: "Crypto", package: "swift-crypto")]
    ),
    .executableTarget(name: "DiemVectors", dependencies: ["DiemSwiftCrypto"]),
    .testTarget(name: "DiemTests", dependencies: ["DiemSwiftCrypto"]),
  ],
  swiftLanguageModes: [.v6]
)
