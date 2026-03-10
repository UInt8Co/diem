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
    .library(name: "Diem", targets: ["Diem"]),
    .library(name: "DiemSwiftCrypto", targets: ["DiemSwiftCrypto"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0"..<"5.0.0"),
    .package(url: "https://github.com/wendylabsinc/cbor.git", from: "0.7.0"),
  ],
  targets: [
    // Core target: Foundation-free, Swift Embedded supported.
    // No crypto dependency — backends are pluggable via DiemCryptoBackend.
    .target(
      name: "Diem",
      dependencies: [
        .product(name: "CBOR", package: "cbor")
      ]
    ),
    // Swift Crypto backend.
    .target(
      name: "DiemSwiftCrypto",
      dependencies: [
        "Diem",
        .product(name: "Crypto", package: "swift-crypto"),
      ]
    ),
    .testTarget(
      name: "DiemTests",
      dependencies: ["DiemSwiftCrypto"]
    ),
  ],
  swiftLanguageModes: [.v6]
)
