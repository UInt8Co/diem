// swift-tools-version: 6.4
import PackageDescription

/// Gates the profile-hosting server. SwiftPM resolves the server's dependencies only for
/// packages that enable it, so app consumers of the client libraries never fetch them.
let server = "ProfileHostingServer"

func serverProduct(_ name: String, _ package: String) -> Target.Dependency {
  .product(name: name, package: package, condition: .when(traits: [server]))
}

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
    // Foundation-free profile hosting, HTTP transport and proof-of-work interfaces.
    .library(name: "DiemProfileHostingClient", targets: ["DiemProfileHostingClient"]),
    // A CryptoBackend on Swift Crypto, with Secure Enclave keys on Apple platforms.
    .library(name: "DiemSwiftCrypto", targets: ["DiemSwiftCrypto"]),
    // A Hummingbird profile host with SQLite name claims; empty without the trait.
    .library(name: "DiemProfileHosting", targets: ["DiemProfileHosting"]),
    // The standalone profile host.
    .executable(name: "diem-profile-hosting", targets: ["DiemProfileHostingServer"]),
    // A clock-controlled Swift Crypto backend and an in-memory profile host for tests.
    .library(name: "DiemTesting", targets: ["DiemTesting"]),
    // Writes cross-language wire vectors.
    .executable(name: "diem-vectors", targets: ["DiemVectors"]),
  ],
  traits: [
    .trait(name: server, description: "Build the profile-hosting server and its executable."),
    .default(enabledTraits: []),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-crypto.git", from: "5.0.0"),
    .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.5.0"),
    .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.27.0"),
    .package(url: "https://github.com/vapor/fluent-kit.git", from: "1.57.0"),
    .package(url: "https://github.com/vapor/fluent-sqlite-driver.git", from: "4.9.0"),
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.103.0"),
    .package(url: "https://github.com/apple/swift-http-types.git", from: "1.8.0"),
    .package(url: "https://github.com/apple/swift-log.git", from: "1.15.1"),
    .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.8.2"),
  ],
  targets: [
    .target(name: "Diem"),
    .target(name: "DiemProfileHostingClient", dependencies: ["Diem"]),
    .target(
      name: "DiemSwiftCrypto",
      dependencies: ["Diem", .product(name: "Crypto", package: "swift-crypto")]
    ),
    .target(
      name: "DiemProfileHosting",
      dependencies: [
        "Diem", "DiemProfileHostingClient", "DiemSwiftCrypto",
        serverProduct("Hummingbird", "hummingbird"),
        serverProduct("FluentKit", "fluent-kit"),
        serverProduct("FluentSQL", "fluent-kit"),
        serverProduct("FluentSQLiteDriver", "fluent-sqlite-driver"),
        serverProduct("NIOCore", "swift-nio"),
        serverProduct("NIOPosix", "swift-nio"),
        serverProduct("HTTPTypes", "swift-http-types"),
        serverProduct("Logging", "swift-log"),
      ]
    ),
    .executableTarget(
      name: "DiemProfileHostingServer",
      dependencies: [
        .target(name: "DiemProfileHosting", condition: .when(traits: [server])),
        serverProduct("ArgumentParser", "swift-argument-parser"),
        serverProduct("Logging", "swift-log"),
      ]
    ),
    .target(
      name: "DiemTesting",
      dependencies: ["Diem", "DiemSwiftCrypto", "DiemProfileHostingClient"]
    ),
    .executableTarget(name: "DiemVectors", dependencies: ["DiemSwiftCrypto"]),
    .testTarget(name: "DiemTests", dependencies: ["DiemTesting", "DiemSwiftCrypto"]),
    .testTarget(name: "DiemProfileHostingClientTests",
      dependencies: ["DiemProfileHostingClient", "DiemTesting"]),
    .testTarget(
      name: "DiemProfileHostingTests",
      dependencies: [
        "DiemProfileHosting", "DiemSwiftCrypto", "DiemTesting",
        serverProduct("Hummingbird", "hummingbird"),
        serverProduct("HummingbirdTesting", "hummingbird"),
        serverProduct("HTTPTypes", "swift-http-types"),
      ]
    ),
  ],
  swiftLanguageModes: [.v6]
)
