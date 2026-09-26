// swift-tools-version: 6.3
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
    // Portable CBOR and key operations, including Swift Embedded targets.
    .library(name: "DiemPortable", targets: ["DiemPortable"]),
    // Reusable encryption and private share primitives.
    .library(name: "Diem", targets: ["Diem"]),
    // No-op crypto backend for tests.
    .library(name: "DiemMocks", targets: ["DiemMocks"]),
    // Swift Crypto backend (HPKE classic; PQC on OS 26+).
    .library(name: "DiemSwiftCrypto", targets: ["DiemSwiftCrypto"]),
    // Share storage contracts and backends.
    .library(name: "DiemStores", targets: ["DiemStores"]),
    .library(name: "DiemStoresInMemory", targets: ["DiemStoresInMemory"]),
    .library(name: "DiemStoresKeychain", targets: ["DiemStoresKeychain"]),
    .library(name: "DiemSecretMemory", targets: ["DiemSecretMemory"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),
    .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.0.0"),
  ],
  targets: [
    // MARK: Core
    .target(name: "DiemPortable"),
    .target(
      name: "Diem",
      dependencies: ["DiemPortable"]
    ),
    .target(
      name: "DiemMocks",
      dependencies: ["Diem"]
    ),
    .target(
      name: "DiemSwiftCrypto",
      dependencies: [
        "Diem",
        .product(name: "Crypto", package: "swift-crypto"),
      ]
    ),
    .target(name: "DiemSecretMemory"),

    // MARK: Stores
    .target(
      name: "DiemStores",
      dependencies: ["Diem"]
    ),
    .target(
      name: "DiemStoresInMemory",
      dependencies: ["Diem", "DiemStores"]
    ),
    .target(
      name: "DiemStoresKeychain",
      dependencies: [
        "Diem",
        "DiemStores",
        "DiemSwiftCrypto",
      ]
    ),

    // MARK: Tests
    .testTarget(
      name: "DiemTests",
      dependencies: [
        "DiemSwiftCrypto",
        "DiemStoresInMemory",
      ]
    ),
  ],
  swiftLanguageModes: [.v6]
)
