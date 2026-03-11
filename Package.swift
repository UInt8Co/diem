// swift-tools-version: 6.3
import PackageDescription

let package = Package(
  name: "Diem",
  platforms: [
    .macOS(.v14),
    .iOS(.v17),
    .tvOS(.v17),
    .watchOS(.v10),
  ],
  products: [
    // Core types + pluggable crypto protocol. Foundation-free. Swift Embedded compatible.
    .library(name: "Diem", targets: ["Diem"]),
    // No-op crypto backend for tests and Embedded targets.
    .library(name: "DiemMocks", targets: ["DiemMocks"]),
    // Swift Crypto backend (HPKE classic; PQC on OS 26+).
    .library(name: "DiemSwiftCrypto", targets: ["DiemSwiftCrypto"]),
    // ProfileStore + IdentityStore protocols. Foundation-free. Swift Embedded compatible.
    .library(name: "DiemStores", targets: ["DiemStores"]),
    // In-memory ProfileStore and IdentityStore with secondary key-ID indexes.
    .library(name: "DiemStoresInMemory", targets: ["DiemStoresInMemory"]),
    // GRDB (SQLite) backed ProfileStore.
    .library(name: "DiemStoresGRDB", targets: ["DiemStoresGRDB"]),
    // Keychain-backed IdentityStore (Apple platforms only).
    .library(name: "DiemStoresKeychain", targets: ["DiemStoresKeychain"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0"..<"5.0.0"),
    .package(url: "https://github.com/wendylabsinc/cbor.git", from: "0.7.0"),
    .package(url: "https://github.com/groue/GRDB.swift.git", from: "7.0.0"),
  ],
  targets: [
    // MARK: Core
    .target(
      name: "Diem",
      dependencies: [
        .product(name: "CBOR", package: "cbor"),
      ]
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

    // MARK: Stores
    .target(
      name: "DiemStores",
      dependencies: ["Diem"]
    ),
    .target(
      name: "DiemStoresInMemory",
      dependencies: ["DiemStores"]
    ),
    .target(
      name: "DiemStoresGRDB",
      dependencies: [
        "DiemStores",
        .product(name: "GRDB", package: "GRDB.swift"),
      ]
    ),
    .target(
      name: "DiemStoresKeychain",
      dependencies: [
        "DiemStores",
        "DiemSwiftCrypto",
      ]
    ),

    // MARK: Tests
    .testTarget(
      name: "DiemTests",
      dependencies: [
        "DiemSwiftCrypto",
        "DiemMocks",
        "DiemStoresInMemory",
      ]
    ),
  ],
  swiftLanguageModes: [.v6]
)
