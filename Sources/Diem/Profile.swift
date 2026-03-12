import CBOR

// MARK: - KeyType

/// The functional role of a cryptographic key within a ``Profile``.
public enum KeyType: UInt64, Sendable, Hashable {
  /// A signing key (Ed25519 for classic, ML-DSA-65 for PQC).
  case signing = 0
  /// A key-agreement / encryption key (X25519 for classic, X-Wing for PQC).
  case keyAgreement = 1
}

// MARK: - PublicKeyEntry

/// A single public key entry stored inside a ``Profile``.
///
/// Each entry carries a stable ``id`` (backend-defined fingerprint, typically SHA-256 of
/// the raw public key), the key's ``keyType``, the ``cryptoSet`` it belongs to, and
/// the raw public key bytes.
public struct PublicKeyEntry: Sendable, Hashable, Identifiable {
  /// A backend-defined fingerprint of ``rawBytes``, used as a stable identifier.
  public let id: [UInt8]
  /// Whether this is a signing or key-agreement key.
  public let keyType: KeyType
  /// Which crypto set this key belongs to.
  public let cryptoSet: CryptoSet
  /// The raw public key bytes.
  public let rawBytes: [UInt8]

  public init(id: [UInt8], keyType: KeyType, cryptoSet: CryptoSet, rawBytes: [UInt8]) {
    self.id = id
    self.keyType = keyType
    self.cryptoSet = cryptoSet
    self.rawBytes = rawBytes
  }

  /// Hexadecimal string representation of the key ID.
  public var hexID: String { id.hexString }
}

extension PublicKeyEntry {
  private enum Field: UInt64 {
    case id = 0
    case keyType = 1
    case cryptoSet = 2
    case rawBytes = 3
  }

  /// Encodes this entry as a CBOR map with integer keys.
  public func toCBOR() -> CBOR {
    .map([
      CBORMapPair(key: .unsignedInt(Field.id.rawValue), value: .byteString(ArraySlice(id))),
      CBORMapPair(
        key: .unsignedInt(Field.keyType.rawValue), value: .unsignedInt(keyType.rawValue)),
      CBORMapPair(
        key: .unsignedInt(Field.cryptoSet.rawValue), value: .unsignedInt(cryptoSet.rawValue)),
      CBORMapPair(
        key: .unsignedInt(Field.rawBytes.rawValue), value: .byteString(ArraySlice(rawBytes))),
    ])
  }

  /// Decodes a ``PublicKeyEntry`` from a CBOR map.
  public static func fromCBOR(_ cbor: CBOR) throws -> PublicKeyEntry {
    guard let pairs = try cbor.mapValue() else { throw DiemError.invalidCBOR }
    var id: [UInt8]?
    var keyType: KeyType?
    var cryptoSet: CryptoSet?
    var rawBytes: [UInt8]?
    for pair in pairs {
      guard case .unsignedInt(let k) = pair.key else { continue }
      switch k {
      case Field.id.rawValue:
        id = pair.value.byteStringValue()
      case Field.keyType.rawValue:
        if case .unsignedInt(let v) = pair.value { keyType = KeyType(rawValue: v) }
      case Field.cryptoSet.rawValue:
        if case .unsignedInt(let v) = pair.value { cryptoSet = CryptoSet(rawValue: v) }
      case Field.rawBytes.rawValue:
        rawBytes = pair.value.byteStringValue()
      default:
        break
      }
    }
    guard let id, let keyType, let cryptoSet, let rawBytes else {
      throw DiemError.missingField("PublicKeyEntry: id, keyType, cryptoSet, or rawBytes missing")
    }
    return PublicKeyEntry(id: id, keyType: keyType, cryptoSet: cryptoSet, rawBytes: rawBytes)
  }
}

// MARK: - Profile

/// The public-facing portion of an ``Identity``.
///
/// A ``Profile`` is safe to share with other parties. It contains a stable random ``id``,
/// one or more public keys (across one or more ``CryptoSet``s), a human-readable ``name``,
/// optional validity timestamps, and optional user-defined ``extensions`` as a CBOR value.
///
/// Serialised as a CBOR map with integer keys.
public struct Profile: Sendable, Identifiable {
  /// A stable 16-byte random identifier for this profile, generated at identity creation.
  public let id: [UInt8]
  /// The public key entries associated with this profile.
  public let keys: [PublicKeyEntry]
  /// A human-readable name for this identity.
  public let name: String
  /// Unix timestamp (seconds since epoch) when this profile was created, if present.
  public let createdAt: UInt64?
  /// Unix timestamp (seconds since epoch) after which this profile should be considered expired.
  public let expiresAt: UInt64?
  /// User-defined metadata as a CBOR value (typically a CBOR map).
  public let extensions: CBOR?

  public init(
    id: [UInt8],
    keys: [PublicKeyEntry],
    name: String,
    createdAt: UInt64? = nil,
    expiresAt: UInt64? = nil,
    extensions: CBOR? = nil
  ) {
    self.id = id
    self.keys = keys
    self.name = name
    self.createdAt = createdAt
    self.expiresAt = expiresAt
    self.extensions = extensions
  }

  /// A lowercase hex string representation of ``id``, suitable for display and logging.
  public var hexID: String {
    id.hexString
  }
}

extension Profile {
  private enum Field: UInt64 {
    case id = 0
    case keys = 1
    case name = 2
    case createdAt = 3
    case expiresAt = 4
    case extensions = 5
  }

  /// Encodes this profile as a CBOR map.
  public func toCBOR() -> CBOR {
    var pairs: [CBORMapPair] = [
      CBORMapPair(
        key: .unsignedInt(Field.id.rawValue),
        value: .byteString(ArraySlice(id))
      ),
      CBORMapPair(
        key: .unsignedInt(Field.keys.rawValue),
        value: .array(keys.map { $0.toCBOR() })
      ),
      CBORMapPair(
        key: .unsignedInt(Field.name.rawValue),
        value: .textString(name)
      ),
    ]
    if let createdAt {
      pairs.append(
        CBORMapPair(key: .unsignedInt(Field.createdAt.rawValue), value: .unsignedInt(createdAt)))
    }
    if let expiresAt {
      pairs.append(
        CBORMapPair(key: .unsignedInt(Field.expiresAt.rawValue), value: .unsignedInt(expiresAt)))
    }
    if let extensions {
      pairs.append(
        CBORMapPair(key: .unsignedInt(Field.extensions.rawValue), value: extensions))
    }
    return .map(pairs)
  }

  /// Decodes a ``Profile`` from a CBOR map.
  public static func fromCBOR(_ cbor: CBOR) throws -> Profile {
    guard let pairs = try cbor.mapValue() else { throw DiemError.invalidCBOR }
    var id: [UInt8]?
    var keys: [PublicKeyEntry]?
    var name: String?
    var createdAt: UInt64?
    var expiresAt: UInt64?
    var extensions: CBOR?
    for pair in pairs {
      guard case .unsignedInt(let k) = pair.key else { continue }
      switch k {
      case Field.id.rawValue:
        id = pair.value.byteStringValue()
      case Field.keys.rawValue:
        let elements = try pair.value.arrayValue() ?? []
        keys = try elements.map { try PublicKeyEntry.fromCBOR($0) }
      case Field.name.rawValue:
        name = pair.value.stringValue
      case Field.createdAt.rawValue:
        if case .unsignedInt(let v) = pair.value { createdAt = v }
      case Field.expiresAt.rawValue:
        if case .unsignedInt(let v) = pair.value { expiresAt = v }
      case Field.extensions.rawValue:
        extensions = pair.value
      default:
        break
      }
    }
    guard let id, let keys, let name else {
      throw DiemError.missingField("Profile: id, keys, or name missing")
    }
    return Profile(
      id: id, keys: keys, name: name, createdAt: createdAt, expiresAt: expiresAt,
      extensions: extensions)
  }

  /// Serialises this profile to CBOR bytes.
  public func encode() -> [UInt8] { toCBOR().encode() }

  /// Deserialises a ``Profile`` from CBOR bytes.
  public static func decode(_ bytes: [UInt8]) throws -> Profile {
    let cbor: CBOR
    do { cbor = try CBOR.decode(bytes) } catch { throw DiemError.invalidCBOR }
    return try fromCBOR(cbor)
  }
}
