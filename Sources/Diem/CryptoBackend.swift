/// Platform cryptography and wall-clock time for Diem.
///
/// A backend creates and restores private keys, verifies signatures and seals data to
/// encryption keys. Failures throw ``DiemError``.
public protocol CryptoBackend: Sendable {
  /// The current time in seconds since the Unix epoch.
  var now: UInt64 { get }

  /// `count` cryptographically secure random bytes.
  func randomBytes(count: Int) -> [UInt8]

  /// A new software signing key, or the one whose secret is `rawRepresentation`.
  func makePrivateKey(_ algorithm: PublicKey.Algorithm, restoring rawRepresentation: [UInt8]?)
    async throws -> PrivateKey

  /// Whether `signature` is `key`'s signature over `message`.
  func isValidSignature(_ signature: [UInt8], for message: [UInt8], by key: PublicKey)
    async throws -> Bool

  /// A new software encryption key, or the one whose secret is `rawRepresentation`.
  func makeEncryptionKey(
    _ algorithm: EncryptionPublicKey.Algorithm, restoring rawRepresentation: [UInt8]?
  ) async throws -> EncryptionPrivateKey

  /// `plaintext` sealed to `key`. `context` is both the HPKE info and the associated data.
  func seal(_ plaintext: [UInt8], to key: EncryptionPublicKey, context: [UInt8]) async throws
    -> SealedBox
}

extension CryptoBackend {
  /// A new software signing key.
  public func makePrivateKey(_ algorithm: PublicKey.Algorithm = .ed25519) async throws
    -> PrivateKey
  {
    try await makePrivateKey(algorithm, restoring: nil)
  }

  /// A new software encryption key.
  public func makeEncryptionKey(_ algorithm: EncryptionPublicKey.Algorithm = .x25519)
    async throws -> EncryptionPrivateKey
  {
    try await makeEncryptionKey(algorithm, restoring: nil)
  }
}
