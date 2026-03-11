import Diem

/// A no-op ``DiemCryptoBackend`` for use in tests and on Embedded targets.
///
/// - ``supportedCryptoSets`` is empty — all crypto operations throw
///   ``DiemError/unsupportedCryptoSet(_:)``.
/// - ``keyID(publicKey:)`` always returns 32 zero bytes.
/// - ``generateRandomBytes(count:)`` always returns zero bytes.
public struct MockCryptoBackend: DiemCryptoBackend, Sendable {
  public init() {}

  public var supportedCryptoSets: Set<CryptoSet> { [] }

  public func generateSigningKeyPair(for cryptoSet: CryptoSet) throws -> (
    publicKey: [UInt8], privateKey: [UInt8]
  ) {
    throw DiemError.unsupportedCryptoSet(cryptoSet)
  }

  public func generateEncryptionKeyPair(for cryptoSet: CryptoSet) throws -> (
    publicKey: [UInt8], privateKey: [UInt8]
  ) {
    throw DiemError.unsupportedCryptoSet(cryptoSet)
  }

  public func sign(message: [UInt8], privateKey: [UInt8], cryptoSet: CryptoSet) throws -> [UInt8] {
    throw DiemError.unsupportedCryptoSet(cryptoSet)
  }

  public func verify(
    signature: [UInt8], message: [UInt8], publicKey: [UInt8], cryptoSet: CryptoSet
  ) throws -> Bool {
    throw DiemError.unsupportedCryptoSet(cryptoSet)
  }

  public func hpkeEncrypt(
    plaintext: [UInt8], recipientPublicKey: [UInt8], cryptoSet: CryptoSet
  ) throws -> (encapsulatedKey: [UInt8], ciphertext: [UInt8]) {
    throw DiemError.unsupportedCryptoSet(cryptoSet)
  }

  public func hpkeDecrypt(
    ciphertext: [UInt8], encapsulatedKey: [UInt8], recipientPrivateKey: [UInt8],
    cryptoSet: CryptoSet
  ) throws -> [UInt8] {
    throw DiemError.unsupportedCryptoSet(cryptoSet)
  }

  public func keyID(publicKey: [UInt8]) -> [UInt8] {
    [UInt8](repeating: 0, count: 32)
  }

  public func generateRandomBytes(count: Int) -> [UInt8] {
    [UInt8](repeating: 0, count: count)
  }
}
