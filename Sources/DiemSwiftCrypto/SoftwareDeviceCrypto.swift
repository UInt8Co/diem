import Crypto
import Diem
import Foundation

/// Independent signing and wrapping algorithms; the selected algorithm is part
/// of every public key's canonical identity. Software protection is always explicit.
public struct SoftwareDeviceCrypto: DeviceCrypto {
  public init() {}
  public func sha256(_ message: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: message)) }
  public func randomBytes(count: Int) -> [UInt8] {
    var rng = SystemRandomNumberGenerator()
    return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &rng) }
  }
  public func verify(_ signature: [UInt8], message: [UInt8], key: DevicePublicKey) throws(DiemError)
    -> Bool
  {
    try normalizeCryptoFailure(.verificationFailed) {
      try verifyImplementation(signature, message: message, key: key)
    }
  }
  private func verifyImplementation(_ signature: [UInt8], message: [UInt8], key: DevicePublicKey)
    throws -> Bool
  {
    guard signature.count == (key.algorithm == .mlDSA65 ? 3309 : 64) else { return false }
    switch key.algorithm {
    case .ed25519:
      return try Curve25519.Signing.PublicKey(rawRepresentation: key.rawRepresentation)
        .isValidSignature(signature, for: message)
    case .p256Signing:
      return try P256.Signing.PublicKey(x963Representation: key.rawRepresentation)
        .isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: signature), for: message)
    case .mlDSA65:
      if #available(macOS 26, iOS 26, watchOS 26, tvOS 26, visionOS 26, *) {
        return try MLDSA65.PublicKey(rawRepresentation: key.rawRepresentation).isValidSignature(
          signature, for: message)
      }
      throw DiemError.unsupportedAlgorithm(key.algorithm)
    default: throw DiemError.roleConfusion
    }
  }
  public func seal(_ plaintext: [UInt8], to key: DevicePublicKey, context: [UInt8])
    throws(DiemError) -> WrappedSecret
  {
    try normalizeCryptoFailure(.encryptionFailed) {
      try sealImplementation(plaintext, to: key, context: context)
    }
  }
  private func sealImplementation(
    _ plaintext: [UInt8], to key: DevicePublicKey,
    context: [UInt8]
  ) throws -> WrappedSecret {
    var sender: HPKE.Sender
    switch key.algorithm {
    case .x25519:
      sender = try HPKE.Sender(
        recipientKey: Curve25519.KeyAgreement.PublicKey(rawRepresentation: key.rawRepresentation),
        ciphersuite: .Curve25519_SHA256_ChachaPoly, info: Data(context))
    case .p256Agreement:
      sender = try HPKE.Sender(
        recipientKey: P256.KeyAgreement.PublicKey(x963Representation: key.rawRepresentation),
        ciphersuite: .P256_SHA256_AES_GCM_256, info: Data(context))
    case .xWing:
      if #available(macOS 26, iOS 26, watchOS 26, tvOS 26, visionOS 26, *) {
        sender = try HPKE.Sender(
          recipientKey: XWingMLKEM768X25519.PublicKey(rawRepresentation: key.rawRepresentation),
          ciphersuite: .XWingMLKEM768X25519_SHA256_AES_GCM_256, info: Data(context))
      } else {
        throw DiemError.unsupportedAlgorithm(key.algorithm)
      }
    default: throw DiemError.roleConfusion
    }
    return try WrappedSecret(
      encapsulatedKey: Array(sender.encapsulatedKey),
      ciphertext: Array(sender.seal(plaintext, authenticating: context)))
  }
}

public struct SoftwareSigningKey: DeviceSigningKey {
  private let sign: @Sendable ([UInt8]) throws -> [UInt8]
  public let publicKey: DevicePublicKey
  public let protection = KeyProtection.software
  /// Optional software-backend persistence. Store only in protected credential storage.
  /// This is never present on hardware handles or in public identity records.
  public let softwarePrivateRepresentationForSecureStorage: [UInt8]

  public init(algorithm: KeyAlgorithm, restoring secret: [UInt8]? = nil) throws {
    switch algorithm {
    case .ed25519:
      let key =
        try secret.map { try Curve25519.Signing.PrivateKey(rawRepresentation: $0) }
        ?? Curve25519.Signing.PrivateKey()
      self.publicKey = try DevicePublicKey(
        algorithm: algorithm, rawRepresentation: Array(key.publicKey.rawRepresentation))
      self.softwarePrivateRepresentationForSecureStorage = Array(key.rawRepresentation)
      self.sign = { try Array(key.signature(for: $0)) }
    case .p256Signing:
      let key =
        try secret.map { try P256.Signing.PrivateKey(rawRepresentation: $0) }
        ?? P256.Signing.PrivateKey()
      self.publicKey = try DevicePublicKey(
        algorithm: algorithm, rawRepresentation: Array(key.publicKey.x963Representation))
      self.softwarePrivateRepresentationForSecureStorage = Array(key.rawRepresentation)
      self.sign = { try Array(key.signature(for: $0).rawRepresentation) }
    case .mlDSA65:
      if #available(macOS 26, iOS 26, watchOS 26, tvOS 26, visionOS 26, *) {
        let key =
          try secret.map { try MLDSA65.PrivateKey(seedRepresentation: Data($0), publicKey: nil) }
          ?? MLDSA65.PrivateKey()
        self.publicKey = try DevicePublicKey(
          algorithm: algorithm, rawRepresentation: Array(key.publicKey.rawRepresentation))
        self.softwarePrivateRepresentationForSecureStorage = Array(key.seedRepresentation)
        self.sign = { try Array(key.signature(for: $0)) }
      } else {
        throw DiemError.unsupportedAlgorithm(algorithm)
      }
    default: throw DiemError.roleConfusion
    }
  }
  public func signature(for message: [UInt8]) throws(DiemError) -> [UInt8] {
    try normalizeCryptoFailure(.encryptionFailed) { try sign(message) }
  }
}

public struct SoftwareWrappingKey: DeviceWrappingKey {
  private let openBox: @Sendable (WrappedSecret, [UInt8]) throws -> [UInt8]
  public let publicKey: DevicePublicKey
  public let protection = KeyProtection.software
  public let softwarePrivateRepresentationForSecureStorage: [UInt8]

  public init(algorithm: KeyAlgorithm, restoring secret: [UInt8]? = nil) throws {
    switch algorithm {
    case .x25519:
      let key =
        try secret.map { try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: $0) }
        ?? Curve25519.KeyAgreement.PrivateKey()
      self.publicKey = try DevicePublicKey(
        algorithm: algorithm, rawRepresentation: Array(key.publicKey.rawRepresentation))
      self.softwarePrivateRepresentationForSecureStorage = Array(key.rawRepresentation)
      self.openBox = { box, context in
        var r = try HPKE.Recipient(
          privateKey: key, ciphersuite: .Curve25519_SHA256_ChachaPoly,
          info: Data(context), encapsulatedKey: Data(box.encapsulatedKey))
        return try Array(r.open(box.ciphertext, authenticating: context))
      }
    case .p256Agreement:
      let key =
        try secret.map { try P256.KeyAgreement.PrivateKey(rawRepresentation: $0) }
        ?? P256.KeyAgreement.PrivateKey()
      self.publicKey = try DevicePublicKey(
        algorithm: algorithm, rawRepresentation: Array(key.publicKey.x963Representation))
      self.softwarePrivateRepresentationForSecureStorage = Array(key.rawRepresentation)
      self.openBox = { box, context in
        var r = try HPKE.Recipient(
          privateKey: key, ciphersuite: .P256_SHA256_AES_GCM_256,
          info: Data(context), encapsulatedKey: Data(box.encapsulatedKey))
        return try Array(r.open(box.ciphertext, authenticating: context))
      }
    case .xWing:
      if #available(macOS 26, iOS 26, watchOS 26, tvOS 26, visionOS 26, *) {
        let key =
          try secret.map {
            try XWingMLKEM768X25519.PrivateKey(seedRepresentation: Data($0), publicKey: nil)
          } ?? XWingMLKEM768X25519.PrivateKey()
        self.publicKey = try DevicePublicKey(
          algorithm: algorithm, rawRepresentation: Array(key.publicKey.rawRepresentation))
        self.softwarePrivateRepresentationForSecureStorage = Array(key.seedRepresentation)
        self.openBox = { box, context in
          var r = try HPKE.Recipient(
            privateKey: key, ciphersuite: .XWingMLKEM768X25519_SHA256_AES_GCM_256,
            info: Data(context), encapsulatedKey: Data(box.encapsulatedKey))
          return try Array(r.open(box.ciphertext, authenticating: context))
        }
      } else {
        throw DiemError.unsupportedAlgorithm(algorithm)
      }
    default: throw DiemError.roleConfusion
    }
  }
  public func open(_ box: WrappedSecret, context: [UInt8]) throws(DiemError) -> [UInt8] {
    try normalizeCryptoFailure(.decryptionFailed) { try openBox(box, context) }
  }
}

package func normalizeCryptoFailure<T>(_ failure: DiemError, _ body: () throws -> T)
  throws(DiemError) -> T
{
  do { return try body() } catch { throw error as? DiemError ?? failure }
}
