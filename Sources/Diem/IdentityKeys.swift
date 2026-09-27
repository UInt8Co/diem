/// The public key of an identity. Its ``id`` is the identity's ID.
public struct IdentityPublicKey: Hashable, Sendable {
  public let key: PublicKey

  public init(_ key: PublicKey) { self.key = key }

  /// The identity ID: the SHA-256 digest of the key's encoding.
  public var id: Digest { key.id }
}

/// The private key of an identity. It certifies devices.
public struct IdentityPrivateKey: Sendable {
  let key: PrivateKey

  public init(_ key: PrivateKey) { self.key = key }

  /// A new software identity key.
  public static func generate(
    _ algorithm: PublicKey.Algorithm = .ed25519, using backend: some CryptoBackend
  ) async throws -> Self {
    Self(try await backend.makePrivateKey(algorithm))
  }

  public var publicKey: IdentityPublicKey { IdentityPublicKey(key.publicKey) }
  public var protection: KeyProtection { key.protection }
}

/// The public key of a device. Its ``id`` is the device's ID.
public struct DevicePublicKey: Hashable, Sendable {
  public let key: PublicKey

  public init(_ key: PublicKey) { self.key = key }

  /// The device ID: the SHA-256 digest of the key's encoding.
  public var id: Digest { key.id }
}

/// The private key of a device. It signs profile content and proofs.
public struct DevicePrivateKey: Sendable {
  let key: PrivateKey

  public init(_ key: PrivateKey) { self.key = key }

  /// A new software device key.
  public static func generate(
    _ algorithm: PublicKey.Algorithm = .ed25519, using backend: some CryptoBackend
  ) async throws -> Self {
    Self(try await backend.makePrivateKey(algorithm))
  }

  public var publicKey: DevicePublicKey { DevicePublicKey(key.publicKey) }
  public var protection: KeyProtection { key.protection }
  /// The exportable secret of a software key; `nil` for hardware keys.
  public var rawRepresentation: [UInt8]? { key.rawRepresentation }
}
