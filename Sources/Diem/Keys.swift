/// Where a private key's secret lives.
public enum KeyProtection: Sendable, Hashable {
  /// Secret bytes are in process memory and can be exported.
  case software
  /// The secret never leaves platform hardware such as the Secure Enclave or Android Keystore.
  case hardware
}

/// A public signing key.
public struct PublicKey: Hashable, Sendable {
  /// A signature algorithm. Raw values are wire codes.
  public enum Algorithm: UInt64, Hashable, Sendable, CaseIterable {
    /// Ed25519 with a 32-byte public key and 64-byte signatures.
    case ed25519 = 1
    /// ECDSA P-256 over SHA-256, with a 65-byte SEC1 uncompressed key and 64-byte r‖s signatures.
    case p256 = 2
    /// ML-DSA-65 with a 1952-byte public key.
    case mlDSA65 = 5
  }

  public let algorithm: Algorithm
  public let rawRepresentation: [UInt8]

  /// A key of `algorithm` with raw public key bytes.
  public init(algorithm: Algorithm, rawRepresentation: [UInt8]) throws(DiemError) {
    let length = switch algorithm {
    case .ed25519: 32
    case .p256: 65
    case .mlDSA65: 1952
    }
    guard rawRepresentation.count == length, algorithm != .p256 || rawRepresentation[0] == 4 else {
      throw .invalidKey
    }
    self.algorithm = algorithm
    self.rawRepresentation = rawRepresentation
  }

  /// Decodes a key from its ``encoding``.
  public init(encoding: [UInt8]) throws(DiemError) {
    let (code, raw) = try KeyEncoding.decode(encoding)
    guard let algorithm = Algorithm(rawValue: code) else { throw .invalidKey }
    try self.init(algorithm: algorithm, rawRepresentation: raw)
  }

  /// The algorithm-qualified canonical encoding.
  public var encoding: [UInt8] { KeyEncoding.encode(algorithm.rawValue, rawRepresentation) }

  /// The SHA-256 digest of ``encoding``.
  public var id: Digest { Digest(hashing: encoding) }
}

/// A private signing key held by a backend.
public struct PrivateKey: Sendable {
  public let publicKey: PublicKey
  public let protection: KeyProtection
  /// The exportable secret of a ``KeyProtection/software`` key; `nil` for hardware keys.
  public let rawRepresentation: [UInt8]?
  private let sign: @Sendable ([UInt8]) async throws -> [UInt8]

  /// A key whose signatures `sign` produces. Backends create keys with this initializer.
  public init(
    publicKey: PublicKey, protection: KeyProtection, rawRepresentation: [UInt8]?,
    sign: @escaping @Sendable ([UInt8]) async throws -> [UInt8]
  ) {
    self.publicKey = publicKey
    self.protection = protection
    self.rawRepresentation = rawRepresentation
    self.sign = sign
  }

  /// A signature over `message`.
  public func signature(for message: [UInt8]) async throws -> [UInt8] { try await sign(message) }
}

/// A public key that others encrypt to.
public struct EncryptionPublicKey: Hashable, Sendable {
  /// An HPKE key-encapsulation algorithm. Raw values are wire codes.
  public enum Algorithm: UInt64, Hashable, Sendable, CaseIterable {
    /// X25519 with HKDF-SHA256 and ChaCha20-Poly1305.
    case x25519 = 3
    /// P-256 with HKDF-SHA256 and AES-256-GCM, using a 65-byte SEC1 uncompressed key.
    case p256 = 4
    /// X-Wing (ML-KEM-768 with X25519), HKDF-SHA256 and AES-256-GCM.
    case xWing = 6
  }

  public let algorithm: Algorithm
  public let rawRepresentation: [UInt8]

  /// A key of `algorithm` with raw public key bytes.
  public init(algorithm: Algorithm, rawRepresentation: [UInt8]) throws(DiemError) {
    let length = switch algorithm {
    case .x25519: 32
    case .p256: 65
    case .xWing: 1216
    }
    guard rawRepresentation.count == length, algorithm != .p256 || rawRepresentation[0] == 4 else {
      throw .invalidKey
    }
    self.algorithm = algorithm
    self.rawRepresentation = rawRepresentation
  }

  /// Decodes a key from its ``encoding``.
  public init(encoding: [UInt8]) throws(DiemError) {
    let (code, raw) = try KeyEncoding.decode(encoding)
    guard let algorithm = Algorithm(rawValue: code) else { throw .invalidKey }
    try self.init(algorithm: algorithm, rawRepresentation: raw)
  }

  /// The algorithm-qualified canonical encoding.
  public var encoding: [UInt8] { KeyEncoding.encode(algorithm.rawValue, rawRepresentation) }

  /// The SHA-256 digest of ``encoding``.
  public var id: Digest { Digest(hashing: encoding) }
}

/// A private decryption key held by a backend.
public struct EncryptionPrivateKey: Sendable {
  public let publicKey: EncryptionPublicKey
  public let protection: KeyProtection
  /// The exportable secret of a ``KeyProtection/software`` key; `nil` for hardware keys.
  public let rawRepresentation: [UInt8]?
  private let openBox: @Sendable (SealedBox, [UInt8]) async throws -> [UInt8]

  /// A key whose boxes `open` decrypts. Backends create keys with this initializer.
  public init(
    publicKey: EncryptionPublicKey, protection: KeyProtection, rawRepresentation: [UInt8]?,
    open: @escaping @Sendable (SealedBox, [UInt8]) async throws -> [UInt8]
  ) {
    self.publicKey = publicKey
    self.protection = protection
    self.rawRepresentation = rawRepresentation
    self.openBox = open
  }

  /// The plaintext of `box`, sealed to this key with `context`.
  public func open(_ box: SealedBox, context: [UInt8]) async throws -> [UInt8] {
    try await openBox(box, context)
  }
}

/// An RFC 9180 base-mode HPKE ciphertext.
public struct SealedBox: Hashable, Sendable {
  public let encapsulatedKey: [UInt8]
  public let ciphertext: [UInt8]

  public init(encapsulatedKey: [UInt8], ciphertext: [UInt8]) {
    self.encapsulatedKey = encapsulatedKey
    self.ciphertext = ciphertext
  }
}

enum KeyEncoding {
  static func encode(_ algorithm: UInt64, _ raw: [UInt8]) -> [UInt8] {
    CBOR.array([.text("Diem/key"), .unsigned(2), .unsigned(algorithm), .bytes(raw)]).encoded
  }

  static func decode(_ encoding: [UInt8]) throws(DiemError) -> (UInt64, [UInt8]) {
    let a = try CBOR(decoding: encoding).arrayValue(count: 4)
    guard a[0] == .text("Diem/key"), a[1] == .unsigned(2) else { throw .invalidKey }
    return try (a[2].unsignedValue(), a[3].bytesValue())
  }
}
