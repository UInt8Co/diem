/// Wire values identify both the algorithm and the key's role. P-256 uses SEC1
/// uncompressed public keys and IEEE P1363 (r || s) ECDSA signatures over SHA-256.
public enum KeyAlgorithm: UInt64, Sendable, CaseIterable {
  case ed25519 = 1
  case p256Signing = 2
  case x25519 = 3
  case p256Agreement = 4
  case mlDSA65 = 5
  case xWing = 6

  public var isSigning: Bool { self == .ed25519 || self == .p256Signing || self == .mlDSA65 }
}

public struct DevicePublicKey: Sendable, Hashable {
  public let algorithm: KeyAlgorithm
  public let rawRepresentation: [UInt8]

  public init(algorithm: KeyAlgorithm, rawRepresentation: [UInt8]) throws(DiemError) {
    let p256 = algorithm == .p256Signing || algorithm == .p256Agreement
    let length = algorithm == .mlDSA65 ? 1952 : algorithm == .xWing ? 1216 : p256 ? 65 : 32
    guard rawRepresentation.count == length, !p256 || rawRepresentation[0] == 4 else {
      throw DiemError.invalidKey
    }
    self.algorithm = algorithm
    self.rawRepresentation = rawRepresentation
  }

  /// keyID = SHA-256(CBOR(["Diem/key", 2, algorithm, public-key bytes])).
  public var encoding: [UInt8] {
    CBOR.array([
      .textString("Diem/key"), .unsignedInt(2), .unsignedInt(algorithm.rawValue),
      bytes(rawRepresentation),
    ]).encode()
  }

  public func id(using crypto: some DeviceCrypto) -> [UInt8] { crypto.sha256(encoding) }

  public static func decode(_ encoded: [UInt8]) throws(DiemError) -> Self {
    let a = try CanonicalCBOR.array(encoded, count: 4)
    guard try string(a[0]) == "Diem/key", try uint(a[1]) == 2,
      let algorithm = try KeyAlgorithm(rawValue: uint(a[2]))
    else { throw DiemError.invalidKey }
    return try Self(algorithm: algorithm, rawRepresentation: octets(a[3]))
  }
}

/// Protection describes the actual backend. Non-extractable software is not hardware.
public enum KeyProtection: String, Sendable {
  case software, secureEnclave, androidTEE, androidStrongBox
}

/// Opaque, destination-generated key operations. No private byte requirement.
public protocol DeviceSigningKey: Sendable {
  var publicKey: DevicePublicKey { get }
  var protection: KeyProtection { get }
  func signature(for message: [UInt8]) throws(DiemError) -> [UInt8]
}

public protocol DeviceWrappingKey: Sendable {
  var publicKey: DevicePublicKey { get }
  var protection: KeyProtection { get }
  func open(_ box: WrappedSecret, context: [UInt8]) throws(DiemError) -> [UInt8]
}

public struct WrappedSecret: Sendable, Equatable {
  public let encapsulatedKey: [UInt8]
  public let ciphertext: [UInt8]
  public init(encapsulatedKey: [UInt8], ciphertext: [UInt8]) {
    self.encapsulatedKey = encapsulatedKey
    self.ciphertext = ciphertext
  }
}

/// Public verification and encryption are separate from private device key custody.
/// The portable protocol/types layer has no Foundation or platform dependency.
public protocol DeviceCrypto: Sendable {
  func sha256(_ message: [UInt8]) -> [UInt8]
  func randomBytes(count: Int) -> [UInt8]
  func verify(_ signature: [UInt8], message: [UInt8], key: DevicePublicKey) throws(DiemError)
    -> Bool
  func seal(_ plaintext: [UInt8], to key: DevicePublicKey, context: [UInt8]) throws(DiemError)
    -> WrappedSecret
}
