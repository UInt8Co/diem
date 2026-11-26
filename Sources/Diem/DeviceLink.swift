/// The public keys and capabilities of a device asking to join an existing identity.
///
/// The new device shows the request's ``DeviceLinkCode`` as a QR code and sends the
/// request itself to the approving device over any channel; the code binds the exact
/// request bytes.
public struct DeviceLinkRequest: Hashable, Sendable {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyDevice: UInt64 = 2
  public static let cborKeyRecipient: UInt64 = 3
  public static let cborKeyLabel: UInt64 = 4
  public static let cborKeyVerifies: UInt64 = 5
  /// The largest encoding, including retained unknown fields.
  public static let maximumBytes = 4096

  /// The new device's key.
  public let device: DevicePublicKey
  /// The P-256 key the response is sealed to.
  public let recipient: EncryptionPublicKey
  /// Untrusted display text, between 1 and 64 UTF-8 bytes.
  public let label: String
  /// The signature algorithms the new device can verify, without repeats.
  public let verifies: [PublicKey.Algorithm]
  private var extensions = CBOR.Record()

  public init(
    device: DevicePublicKey, recipient: EncryptionPublicKey, label: String,
    verifies: [PublicKey.Algorithm]
  ) throws(DiemError) {
    guard (1...64).contains(label.utf8.count), !verifies.isEmpty,
      Set(verifies).count == verifies.count
    else { throw .invalidDeviceLink }
    guard recipient.algorithm == .p256 else { throw .unsupportedAlgorithm }
    self.device = device
    self.recipient = recipient
    self.label = label
    self.verifies = verifies
    guard encoding.count <= Self.maximumBytes else { throw .invalidDeviceLink }
  }

  /// Decodes a request from its ``encoding``.
  public init(encoding: [UInt8]) throws(DiemError) {
    let a = try deviceLinkRecord(
      encoding, tag: "Diem/device-link-request", maximumBytes: Self.maximumBytes,
      requiredKeys: Self.cborKeyTag..<(Self.cborKeyVerifies + 1))
    var verifies: [PublicKey.Algorithm] = []
    for code in try a[Self.cborKeyVerifies]!.arrayValue() {
      guard let algorithm = PublicKey.Algorithm(rawValue: try code.unsignedValue()) else {
        throw .unsupportedAlgorithm
      }
      verifies.append(algorithm)
    }
    try self.init(
      device: DevicePublicKey(PublicKey(encoding: a[Self.cborKeyDevice]!.bytesValue())),
      recipient: EncryptionPublicKey(encoding: a[Self.cborKeyRecipient]!.bytesValue()),
      label: a[Self.cborKeyLabel]!.textValue(), verifies: verifies)
    extensions = a.extensions(above: Self.cborKeyVerifies)
  }

  /// The canonical encoding, including retained unknown fields.
  public var encoding: [UInt8] {
    CBOR.record(
      [
        Self.cborKeyTag: .text("Diem/device-link-request"), Self.cborKeyVersion: .unsigned(1),
        Self.cborKeyDevice: .bytes(device.key.encoding),
        Self.cborKeyRecipient: .bytes(recipient.encoding), Self.cborKeyLabel: .text(label),
        Self.cborKeyVerifies: .array(verifies.map { .unsigned($0.rawValue) }),
      ], retaining: extensions
    ).encoded
  }

  /// SHA-256 of the exact canonical request, including unknown fields.
  public var digest: Digest { Digest(hashing: encoding) }

  /// Throws ``DiemError/unsupportedAlgorithm`` unless the new device can verify both the
  /// identity key and the approving device's key. The approver calls it before
  /// certifying the new device.
  public func requireCompatible(identityKey: IdentityPublicKey, device: DevicePublicKey)
    throws(DiemError)
  {
    guard verifies.contains(identityKey.key.algorithm), verifies.contains(device.key.algorithm)
    else { throw .unsupportedAlgorithm }
  }
}

/// The QR-only binding between a request and the response's HPKE context: the request's
/// digest and a fresh 16-byte secret.
///
/// Only the two devices see the code; never send it to a server.
public struct DeviceLinkCode: Hashable, Sendable {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyRequestDigest: UInt64 = 2
  public static let cborKeySecret: UInt64 = 3
  /// The largest encoding.
  public static let maximumBytes = 4096

  public let requestDigest: Digest
  /// 16 random bytes.
  public let secret: [UInt8]
  private var extensions = CBOR.Record()

  public init(requestDigest: Digest, secret: [UInt8]) throws(DiemError) {
    guard secret.count == 16 else { throw .invalidDeviceLink }
    self.requestDigest = requestDigest
    self.secret = secret
  }

  /// A code for `request` with a fresh secret from the backend.
  public init(request: DeviceLinkRequest, using backend: some CryptoBackend) throws(DiemError) {
    try self.init(requestDigest: request.digest, secret: backend.randomBytes(count: 16))
  }

  /// Decodes a code from its ``encoding``.
  public init(encoding: [UInt8]) throws(DiemError) {
    let a = try deviceLinkRecord(
      encoding, tag: "Diem/device-link-code", maximumBytes: Self.maximumBytes,
      requiredKeys: Self.cborKeyTag..<(Self.cborKeySecret + 1))
    try self.init(
      requestDigest: Digest(bytes: a[Self.cborKeyRequestDigest]!.bytesValue()),
      secret: a[Self.cborKeySecret]!.bytesValue())
    extensions = a.extensions(above: Self.cborKeySecret)
  }

  /// The canonical encoding.
  public var encoding: [UInt8] {
    CBOR.record(
      [
        Self.cborKeyTag: .text("Diem/device-link-code"), Self.cborKeyVersion: .unsigned(1),
        Self.cborKeyRequestDigest: .bytes(requestDigest.bytes),
        Self.cborKeySecret: .bytes(secret),
      ], retaining: extensions
    ).encoded
  }

  /// The ``encoding`` as unpadded base64url, for the application's QR URL parameter.
  public var parameter: String { Base64URL.encode(encoding) }

  /// Decodes a code from its strict base64url ``parameter``.
  public init(parameter: String) throws(DiemError) {
    guard let encoding = Base64URL.decode(parameter, maximumBytes: Self.maximumBytes) else {
      throw .invalidDeviceLink
    }
    try self.init(encoding: encoding)
  }

  /// Whether `requestBytes` are exactly the request this code names. Check the received
  /// bytes before decoding or acting on a request.
  public func matches(_ requestBytes: [UInt8]) -> Bool {
    guard requestBytes.count <= DeviceLinkRequest.maximumBytes else { return false }
    let digest = SHA2.sha256(requestBytes)
    var difference: UInt8 = 0
    for index in 0..<32 { difference |= requestDigest.bytes[index] ^ digest[index] }
    return difference == 0
  }
}

/// The canonical HPKE info and associated data of a device-link response.
public struct DeviceLinkContext: Hashable, Sendable {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyRequestDigest: UInt64 = 2
  public static let cborKeySecret: UInt64 = 3
  /// The largest encoding.
  public static let maximumBytes = 4096

  public let requestDigest: Digest
  public let secret: [UInt8]
  private var extensions = CBOR.Record()

  public init(requestDigest: Digest, secret: [UInt8]) throws(DiemError) {
    guard secret.count == 16 else { throw .invalidDeviceLink }
    self.requestDigest = requestDigest
    self.secret = secret
  }

  /// The context of the response to `code`'s request.
  public init(code: DeviceLinkCode) {
    requestDigest = code.requestDigest
    secret = code.secret
  }

  /// Decodes a context from its ``encoding``.
  public init(encoding: [UInt8]) throws(DiemError) {
    let a = try deviceLinkRecord(
      encoding, tag: "Diem/device-link-context", maximumBytes: Self.maximumBytes,
      requiredKeys: Self.cborKeyTag..<(Self.cborKeySecret + 1))
    try self.init(
      requestDigest: Digest(bytes: a[Self.cborKeyRequestDigest]!.bytesValue()),
      secret: a[Self.cborKeySecret]!.bytesValue())
    extensions = a.extensions(above: Self.cborKeySecret)
  }

  /// The canonical encoding.
  public var encoding: [UInt8] {
    CBOR.record(
      [
        Self.cborKeyTag: .text("Diem/device-link-context"), Self.cborKeyVersion: .unsigned(1),
        Self.cborKeyRequestDigest: .bytes(requestDigest.bytes),
        Self.cborKeySecret: .bytes(secret),
      ], retaining: extensions
    ).encoded
  }
}

/// What the approving device sends the new one: its exact published profile, the domain
/// it was published at, optionally the identity seed sealed to the new device, and any
/// application fields.
///
/// Diem neither interprets nor restricts the application fields; each application
/// enforces its own policy for them when it accepts a grant.
public struct DeviceLinkGrant: Hashable, Sendable {
  /// CBOR field keys. Application fields are keyed by ``ApplicationID``.
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyProfile: UInt64 = 2
  public static let cborKeyDomain: UInt64 = 3
  public static let cborKeySeed: UInt64 = 4
  /// The largest encoding.
  public static let maximumBytes = 65_536

  /// The exact signed profile bytes the approving device published.
  public let profile: [UInt8]
  /// The domain the profile was published at.
  public let domain: DomainName
  /// The identity seed, sealed to the request's recipient key, when custody transfers.
  public let seed: SealedIdentitySeed?
  /// Application fields, uninterpreted.
  public let applications: [ApplicationID: CBOR]
  private var extensions: [UInt64: CBOR] = [:]

  /// A grant of `profile`, which must be a well-formed ``ProfileRecord`` encoding.
  public init(
    profile: [UInt8], domain: DomainName, seed: SealedIdentitySeed? = nil,
    applications: [ApplicationID: CBOR] = [:]
  ) throws(DiemError) {
    _ = try ProfileRecord(encoding: profile)
    self.profile = profile
    self.domain = domain
    self.seed = seed
    self.applications = applications
    guard encoding.count <= Self.maximumBytes else { throw .invalidDeviceLink }
  }

  /// A grant of `profile`'s exact encoding.
  public init(
    profile: some Profile, domain: DomainName, seed: SealedIdentitySeed? = nil,
    applications: [ApplicationID: CBOR] = [:]
  ) throws(DiemError) {
    try self.init(profile: profile.encoding, domain: domain, seed: seed, applications: applications)
  }

  /// Decodes a grant from its ``encoding``.
  public init(encoding: [UInt8]) throws(DiemError) {
    let a = try deviceLinkRecord(
      encoding, tag: "Diem/device-link-grant", maximumBytes: Self.maximumBytes,
      requiredKeys: Self.cborKeyTag..<(Self.cborKeyDomain + 1))
    var seed: SealedIdentitySeed?
    if let value = a[Self.cborKeySeed] { seed = try SealedIdentitySeed(encoding: value.bytesValue()) }
    try self.init(
      profile: a[Self.cborKeyProfile]!.bytesValue(),
      domain: DomainName(a[Self.cborKeyDomain]!.textValue()), seed: seed,
      applications: a.applications)
    extensions = a.extensions(above: Self.cborKeySeed).fields
  }

  /// The canonical encoding.
  public var encoding: [UInt8] {
    var fields: [UInt64: CBOR] = [
      Self.cborKeyTag: .text("Diem/device-link-grant"), Self.cborKeyVersion: .unsigned(1),
      Self.cborKeyProfile: .bytes(profile), Self.cborKeyDomain: .text(domain.name),
    ]
    if let seed { fields[Self.cborKeySeed] = .bytes(seed.encoding) }
    return CBOR.record(fields, applications: applications, extensions: extensions).encoded
  }

  /// The grant's profile, decoded as `P` and checked to authorize `request`'s device at
  /// `time` (the backend's current time by default).
  ///
  /// The profile must verify at `time`, list ``domain``, and certify the request's device
  /// in its current generation with a certificate valid at `time`. The new device must
  /// verify both the identity and signing keys' algorithms, and a sealed seed must belong
  /// to the profile's identity and the request's recipient. Applications check their own
  /// acceptance rules on the returned profile.
  public func verify<P: DomainNamedProfile>(
    as type: P.Type, for request: DeviceLinkRequest, at time: UInt64? = nil,
    using backend: some CryptoBackend
  ) async throws -> P {
    let time = time ?? backend.now
    let profile = try P(encoding: profile)
    try await profile.verify(using: backend, at: time)
    guard profile.serves(domain) else { throw DiemError.invalidDomain }
    guard profile.devices.contains(where: {
      $0.device == request.device && $0.generation == profile.generation
        && $0.validity.contains(time)
    }) else { throw DiemError.deviceNotListed }
    try request.requireCompatible(identityKey: profile.identityKey, device: profile.signer)
    if let seed {
      guard seed.identityKey == profile.identityKey, seed.recipient == request.recipient else {
        throw DiemError.identityMismatch
      }
    }
    return profile
  }
}

/// A device-link grant sealed with HPKE to the request's recipient key: canonical CBOR
/// `{0: encapsulatedKey, 1: ciphertext}`, whose context is the ``DeviceLinkContext`` of
/// the QR code.
public enum DeviceLinkResponse {
  /// CBOR field keys.
  public static let cborKeyEncapsulatedKey: UInt64 = 0
  public static let cborKeyCiphertext: UInt64 = 1
  /// The largest encoding.
  public static let maximumBytes = 65_536

  /// A grant whose profile, application acceptance and optional identity custody have
  /// all been verified.
  public struct Opened<P: DomainNamedProfile>: Sendable {
    public let grant: DeviceLinkGrant
    /// The grant's profile, decoded as the caller's type.
    public let profile: P
    /// The opened identity seed, when custody transferred.
    public let seed: IdentitySeed?
  }

  /// Seals `grant` for `request`, after checking that `code` names the request and that
  /// the grant verifies as `P` now and passes the application's `accept` check.
  public static func seal<P: DomainNamedProfile>(
    _ grant: DeviceLinkGrant, as type: P.Type, for request: DeviceLinkRequest,
    code: DeviceLinkCode, using backend: some CryptoBackend, accept: (P) throws -> Void
  ) async throws -> [UInt8] {
    guard code.matches(request.encoding) else { throw DiemError.invalidDeviceLink }
    try accept(try await grant.verify(as: type, for: request, using: backend))
    let box = try await backend.seal(
      grant.encoding, to: request.recipient, context: DeviceLinkContext(code: code).encoding)
    let bytes = CBOR.record([
      cborKeyEncapsulatedKey: .bytes(box.encapsulatedKey), cborKeyCiphertext: .bytes(box.ciphertext),
    ]).encoded
    guard bytes.count <= maximumBytes else { throw DiemError.invalidDeviceLink }
    return bytes
  }

  /// Opens a response to `request` with the recipient's key, verifies the grant as `P` at
  /// `time` (the backend's current time by default), applies the application's `accept`
  /// check, and opens any sealed identity seed.
  public static func open<P: DomainNamedProfile>(
    _ bytes: [UInt8], as type: P.Type, recipientKey: EncryptionPrivateKey,
    request: DeviceLinkRequest, code: DeviceLinkCode, at time: UInt64? = nil,
    using backend: some CryptoBackend, accept: (P) throws -> Void
  ) async throws -> Opened<P> {
    guard bytes.count <= maximumBytes, code.matches(request.encoding) else {
      throw DiemError.invalidDeviceLink
    }
    guard recipientKey.publicKey == request.recipient else { throw DiemError.identityMismatch }
    let fields = try CBOR(decoding: bytes).recordValue(
      requiredKeys: cborKeyEncapsulatedKey..<(cborKeyCiphertext + 1))
    let box = try SealedBox(
      encapsulatedKey: fields[cborKeyEncapsulatedKey]!.bytesValue(count: 65),
      ciphertext: fields[cborKeyCiphertext]!.bytesValue())
    guard box.encapsulatedKey.first == 4, box.ciphertext.count >= 16 else {
      throw DiemError.invalidDeviceLink
    }
    var plaintext = try await recipientKey.open(box, context: DeviceLinkContext(code: code).encoding)
    defer { plaintext = [UInt8](repeating: 0, count: plaintext.count) }
    let grant = try DeviceLinkGrant(encoding: plaintext)
    let profile = try await grant.verify(as: type, for: request, at: time, using: backend)
    try accept(profile)
    let seed = try await grant.seed?.open(with: recipientKey, using: backend)
    return Opened(grant: grant, profile: profile, seed: seed)
  }
}

/// A bounded device-link record with a text tag at key 0 and version 1 at key 1. Malformed
/// or oversized records are ``DiemError/invalidDeviceLink``.
private func deviceLinkRecord(
  _ bytes: [UInt8], tag: String, maximumBytes: Int, requiredKeys: Range<UInt64>
) throws(DiemError) -> CBOR.Record {
  guard bytes.count <= maximumBytes,
    let record = try? CBOR(decoding: bytes).recordValue(
      tag: .text(tag), version: 1, requiredKeys: requiredKeys)
  else { throw .invalidDeviceLink }
  return record
}
