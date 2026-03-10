// MARK: - DiemCryptoBackend

/// A pluggable cryptographic backend that performs the low-level operations required by Diem.
///
/// Implementations must be `Sendable`.  The core `Diem` library ships with a
/// ``MockCryptoBackend`` that compiles everywhere (including WASM Embedded) but refuses all
/// operations.  A production-ready backend is provided by `DiemSwiftCrypto` as
/// ``SwiftCryptoBackend``.
///
/// All parameters and return values use `[UInt8]` to remain Foundation-free and
/// embeddable.
public protocol DiemCryptoBackend: Sendable {
  /// The crypto sets this backend is capable of performing operations for.
  var supportedCryptoSets: Set<CryptoSet> { get }

  // MARK: Key generation

  /// Generates a signing key pair for the given crypto set.
  ///
  /// - Returns: `(publicKey, privateKey)` both as raw bytes.
  /// - Throws: ``DiemError/unsupportedCryptoSet(_:)`` if `cryptoSet` is not supported.
  func generateSigningKeyPair(for cryptoSet: CryptoSet) throws -> (
    publicKey: [UInt8], privateKey: [UInt8]
  )

  /// Generates an encryption (key-agreement / KEM) key pair for the given crypto set.
  ///
  /// - Returns: `(publicKey, privateKey)` both as raw bytes.
  /// - Throws: ``DiemError/unsupportedCryptoSet(_:)`` if `cryptoSet` is not supported.
  func generateEncryptionKeyPair(for cryptoSet: CryptoSet) throws -> (
    publicKey: [UInt8], privateKey: [UInt8]
  )

  // MARK: Signing

  /// Signs `message` using the given raw private key bytes.
  ///
  /// - Throws: ``DiemError/invalidKey`` if the key bytes are invalid,
  ///           ``DiemError/encryptionFailed`` if signing fails.
  func sign(message: [UInt8], privateKey: [UInt8], cryptoSet: CryptoSet) throws -> [UInt8]

  /// Verifies `signature` over `message` using the given raw public key bytes.
  ///
  /// - Returns: `true` when the signature is cryptographically valid.
  /// - Throws: ``DiemError/invalidKey`` if the key bytes are invalid.
  func verify(
    signature: [UInt8], message: [UInt8], publicKey: [UInt8], cryptoSet: CryptoSet
  ) throws -> Bool

  // MARK: HPKE

  /// Encrypts `plaintext` for the holder of `recipientPublicKey` using HPKE.
  ///
  /// - Returns: `(encapsulatedKey, ciphertext)` — both must be stored in ``EncryptedMessage``.
  /// - Throws: ``DiemError/invalidKey`` if the public key bytes are invalid,
  ///           ``DiemError/encryptionFailed`` if HPKE setup or sealing fails.
  func hpkeEncrypt(
    plaintext: [UInt8], recipientPublicKey: [UInt8], cryptoSet: CryptoSet
  ) throws -> (encapsulatedKey: [UInt8], ciphertext: [UInt8])

  /// Decrypts HPKE `ciphertext` using the recipient's private key.
  ///
  /// - Throws: ``DiemError/invalidKey`` if the private key bytes are invalid,
  ///           ``DiemError/decryptionFailed`` if HPKE opening fails.
  func hpkeDecrypt(
    ciphertext: [UInt8], encapsulatedKey: [UInt8], recipientPrivateKey: [UInt8],
    cryptoSet: CryptoSet
  ) throws -> [UInt8]

  // MARK: Key ID

  /// Computes a stable, fixed-length identifier for the given raw public key bytes.
  ///
  /// The identifier is used as the ``PublicKeyEntry/id`` and as the key in
  /// ``Identity/privateKeysByKeyID``.  A typical implementation returns SHA-256(publicKey).
  func keyID(publicKey: [UInt8]) -> [UInt8]
}
