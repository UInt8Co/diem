/// An identity's public statement: a signed ``ProfileRecord`` and the application
/// ``Content`` it carries.
///
/// A conforming type decodes and validates its content from a record and says which
/// ``ProfileFields`` publish new content. Keys, devices, revisions, encoding and
/// verification have default implementations. ``ProfileRecord`` is the default profile,
/// whose content is its fields, uninterpreted.
public protocol Profile: Hashable, Sendable {
  /// The application's view of the signed fields.
  associatedtype Content: Hashable, Sendable

  /// The signed record.
  var record: ProfileRecord { get }
  /// The content decoded from ``record``.
  var content: Content { get }

  /// Decodes and validates the content of a well-formed record. ``verify(using:at:)``
  /// checks its signatures and validity.
  init(record: ProfileRecord) throws
  /// The signed fields that publish `content`.
  static func fields(for content: Content) throws -> ProfileFields
}

extension Profile {
  /// Decodes a well-formed profile from its ``encoding``.
  public init(encoding: [UInt8]) throws {
    try self.init(record: ProfileRecord(encoding: encoding))
  }

  /// The canonical encoding.
  public var encoding: [UInt8] { record.encoding }
  /// The identity ID.
  public var id: Digest { record.identityKey.id }
  public var identityKey: IdentityPublicKey { record.identityKey }
  /// The identity's certificates for its devices, all of one generation.
  public var devices: [DeviceCertificate] { record.devices }
  /// The device generation of every listed certificate.
  public var generation: UInt64 { record.generation }
  /// The device that signed the content.
  public var signer: DevicePublicKey { record.signer }
  /// The content revision, starting at 1.
  public var revision: UInt64 { record.revision }
  /// The ``digest`` of the previous revision; `nil` for revision 1.
  public var previousDigest: Digest? { record.previousDigest }
  public var validity: Validity { record.validity }
  /// The digest of this revision's signed content.
  public var digest: Digest { record.signedContent.digest }

  /// The listed device with `id`, if any.
  public func device(_ id: Digest) -> DevicePublicKey? {
    record.devices.first { $0.device.id == id }?.device
  }

  /// Verifies every certificate and the content signature, and that all are valid at
  /// `time` (the backend's current time by default).
  public func verify(using backend: some CryptoBackend, at time: UInt64? = nil) async throws {
    let time = time ?? backend.now
    for certificate in record.devices {
      try await certificate.verify(identityKey: record.identityKey, at: time, using: backend)
    }
    try record.validity.require(at: time, maximumLifetime: ProfileRecord.maximumLifetime)
    try await record.signedContent.verify(by: record.signer.key, using: backend)
  }

  /// The first revision of a new identity publishing `content`, signed by its only
  /// device, `deviceKey`.
  public init(
    publishing content: Content, identityKey: IdentityPrivateKey, deviceKey: DevicePrivateKey,
    profileLifetime: UInt64 = ProfileRecord.defaultLifetime,
    deviceLifetime: UInt64 = DeviceCertificate.defaultLifetime,
    using backend: some CryptoBackend
  ) async throws {
    guard !deviceKey.publicKey.key.hasSameMaterial(as: identityKey.publicKey.key) else {
      throw DiemError.identityMismatch
    }
    let now = backend.now
    _ = try Validity(starting: now, lifetime: profileLifetime)
    let certificate = try await DeviceCertificate.issue(
      by: identityKey, for: deviceKey.publicKey, generation: 1,
      validity: Validity(starting: now, lifetime: deviceLifetime))
    try self.init(record: await ProfileRecord.sign(
      identityKey: identityKey.publicKey, devices: [certificate], by: deviceKey, revision: 1,
      previousDigest: nil,
      validity: ProfileRecord.contentValidity(for: certificate, at: now, lifetime: profileLifetime),
      fields: Self.fields(for: content)))
  }

  /// The next revision, certifying `device` with a recovered identity key and signed by
  /// it. Existing devices and the revision chain are preserved.
  ///
  /// The caller fetches this latest trusted profile and checks its monotonic version
  /// before recovery, then durably stores and publishes the result before using the
  /// new device.
  public func enrolling(
    _ device: DevicePrivateKey, identityKey: IdentityPrivateKey,
    profileLifetime: UInt64 = ProfileRecord.defaultLifetime,
    deviceLifetime: UInt64 = DeviceCertificate.defaultLifetime,
    using backend: some CryptoBackend
  ) async throws -> Self {
    try await verify(using: backend, at: validity.notBefore)
    guard identityKey.publicKey == self.identityKey,
      !device.publicKey.key.hasSameMaterial(as: identityKey.publicKey.key)
    else { throw DiemError.identityMismatch }
    let validity = try Validity(starting: backend.now, lifetime: deviceLifetime)
    let contentValidity = try Validity(starting: backend.now, lifetime: profileLifetime)
    guard contentValidity.expiresAt <= validity.expiresAt else { throw DiemError.invalidValidity }
    let keys = devices.map(\.device).filter { $0 != device.publicKey } + [device.publicKey]
    var certificates: [DeviceCertificate] = []
    for key in keys {
      certificates.append(try await DeviceCertificate.issue(
        by: identityKey, for: key, generation: generation, validity: validity))
    }
    return try Self(record: await ProfileRecord.sign(
      identityKey: self.identityKey, devices: certificates, by: device,
      revision: revision + 1, previousDigest: digest, validity: contentValidity,
      fields: record.fields))
  }
}

/// A profile named by the domains that serve it. A verifier that fetched a profile from a
/// domain checks that the profile serves that domain.
///
/// Domains are a standard signed field of every ``ProfileRecord``. A conforming type
/// states how many it lists and checks them with ``validate(domains:)`` when decoding.
public protocol DomainNamedProfile: Profile {
  /// How many domains a profile of this type lists.
  static var domainCount: ClosedRange<Int> { get }
}

extension DomainNamedProfile {
  public static var domainCount: ClosedRange<Int> { 0...ProfileFields.maximumDomains }

  /// The signed domains that serve this profile, in the publisher's order.
  public var domains: [DomainName] { record.fields.domains }

  /// Whether `domain` serves this profile.
  public func serves(_ domain: DomainName) -> Bool { domains.contains(domain) }

  /// Whether the domain named `name` serves this profile.
  public func serves(_ name: String) -> Bool { domains.contains { $0.name == name } }

  /// Throws ``DiemError/invalidDomain`` unless `domains` has ``domainCount`` entries.
  public static func validate(domains: [DomainName]) throws(DiemError) {
    guard domainCount.contains(domains.count) else { throw .invalidDomain }
  }
}

/// The fields a profile's publisher chooses, all signed in its content: the domains
/// that serve it and the application's own fields.
public struct ProfileFields: Hashable, Sendable {
  /// Content keys from this one up belong to the application; lower keys are Diem's.
  public static let firstApplicationKey: UInt64 = 16
  /// The most domains one profile may list.
  public static let maximumDomains = 16

  /// Distinct domains.
  public var domains: [DomainName]
  /// Application fields, keyed from ``firstApplicationKey`` up.
  public var application: [UInt64: CBOR]

  public init(domains: [DomainName] = [], application: [UInt64: CBOR] = [:]) {
    self.domains = domains
    self.application = application
  }

  /// Decodes fields from their ``encoding``.
  public init(encoding: [UInt8]) throws(DiemError) {
    let a = try CBOR(decoding: encoding).recordValue(
      requiredKeys: ProfileRecord.cborKeyContentDomains..<(ProfileRecord.cborKeyContentDomains + 1))
    // Other Diem keys would be dropped when signed.
    guard a.keys.allSatisfy({ $0 == ProfileRecord.cborKeyContentDomains || $0 >= Self.firstApplicationKey })
    else { throw .invalidEncoding }
    try self.init(content: a)
  }

  /// Decodes the fields of a profile content record.
  init(content: [UInt64: CBOR]) throws(DiemError) {
    var domains: [DomainName] = []
    for domain in try content[ProfileRecord.cborKeyContentDomains]!.arrayValue() {
      domains.append(try DomainName(domain.textValue()))
    }
    self.init(domains: domains, application: content.filter { $0.key >= Self.firstApplicationKey })
    try validate()
  }

  /// A CBOR map of the domains at ``ProfileRecord/cborKeyContentDomains`` and the
  /// application fields at their own keys, as in the signed content.
  public var encoding: [UInt8] { CBOR.record(contentFields).encoded }

  var contentFields: [UInt64: CBOR] {
    application.merging(
      [ProfileRecord.cborKeyContentDomains: .array(domains.map { .text($0.name) })]
    ) { _, domains in domains }
  }

  /// Throws unless the domains are distinct and few enough, and every application key is
  /// the application's.
  func validate() throws(DiemError) {
    guard domains.count <= Self.maximumDomains, Set(domains).count == domains.count else {
      throw .invalidDomain
    }
    guard application.keys.allSatisfy({ $0 >= Self.firstApplicationKey }) else {
      throw .invalidEncoding
    }
  }
}

/// The signed record behind every profile: an identity key, its certified devices, and
/// content signed by one of those devices. As a ``Profile``, its content is its
/// uninterpreted ``fields``.
public struct ProfileRecord: DomainNamedProfile {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyIdentityKey: UInt64 = 2
  public static let cborKeyDevices: UInt64 = 3
  public static let cborKeyContent: UInt64 = 4

  /// CBOR field keys in the signed content. Keys from
  /// ``ProfileFields/firstApplicationKey`` up hold application fields.
  public static let cborKeyContentTag: UInt64 = 0
  public static let cborKeyContentVersion: UInt64 = 1
  public static let cborKeyContentIdentityID: UInt64 = 2
  public static let cborKeyContentGeneration: UInt64 = 3
  public static let cborKeyContentSignerID: UInt64 = 4
  public static let cborKeyContentRevision: UInt64 = 5
  public static let cborKeyContentPreviousDigest: UInt64 = 6
  public static let cborKeyContentNotBefore: UInt64 = 7
  public static let cborKeyContentExpiresAt: UInt64 = 8
  public static let cborKeyContentDomains: UInt64 = 9

  private var extensionFields: [UInt64: CBOR] = [:]

  /// Default publishing lifetime. Applications may choose a different interval.
  public static let defaultLifetime: UInt64 = 24 * 60 * 60
  /// The wire timestamp bound; a profile must also fit its signing certificate.
  public static let maximumLifetime = UInt64(Int64.max)
  /// The most devices one profile may list.
  public static let maximumDevices = 128

  public let identityKey: IdentityPublicKey
  /// The identity's certificates for its devices, all of one generation.
  public let devices: [DeviceCertificate]
  /// The content, signed by ``signer``.
  public let signedContent: SignedMessage

  /// The device generation of every listed certificate.
  public let generation: UInt64
  /// The device that signed ``signedContent``.
  public let signer: DevicePublicKey
  /// The content revision, starting at 1.
  public let revision: UInt64
  /// The digest of the previous revision; `nil` for revision 1.
  public let previousDigest: Digest?
  public let validity: Validity
  /// The signed domains and application fields.
  public let fields: ProfileFields

  public var record: ProfileRecord { self }
  public var content: ProfileFields { fields }
  public init(record: ProfileRecord) { self = record }
  public static func fields(for content: ProfileFields) -> ProfileFields { content }

  /// Decodes a well-formed profile from its encoding. ``verify(using:at:)`` checks its
  /// signatures and validity.
  public init(encoding: [UInt8]) throws(DiemError) {
    let a = try CBOR(decoding: encoding).recordValue(
      requiredKeys: Self.cborKeyTag..<(Self.cborKeyContent + 1))
    guard a[Self.cborKeyTag]! == .text("Diem/profile"), a[Self.cborKeyVersion]! == .unsigned(4)
    else { throw .invalidEncoding }
    let certificates = try a[Self.cborKeyDevices]!.arrayValue()
    var devices: [DeviceCertificate] = []
    for certificate in certificates {
      devices.append(try DeviceCertificate(encoding: certificate.bytesValue()))
    }
    try self.init(
      identityKey: IdentityPublicKey(PublicKey(encoding: a[Self.cborKeyIdentityKey]!.bytesValue())),
      devices: devices,
      signedContent: SignedMessage(encoding: a[Self.cborKeyContent]!.bytesValue()))
    extensionFields = a.filter { $0.key > Self.cborKeyContent }
  }

  private init(identityKey: IdentityPublicKey, devices: [DeviceCertificate], signedContent: SignedMessage)
    throws(DiemError)
  {
    let c = try CBOR(decoding: signedContent.message).recordValue(
      requiredKeys: Self.cborKeyContentTag..<(Self.cborKeyContentDomains + 1))
    guard c[Self.cborKeyContentTag]! == .text("Diem/profile-content"),
      c[Self.cborKeyContentVersion]! == .unsigned(4)
    else {
      throw .invalidEncoding
    }
    guard try Digest(bytes: c[Self.cborKeyContentIdentityID]!.bytesValue()) == identityKey.id else {
      throw .identityMismatch
    }
    generation = try c[Self.cborKeyContentGeneration]!.unsignedValue()
    let signerID = try Digest(bytes: c[Self.cborKeyContentSignerID]!.bytesValue())
    revision = try c[Self.cborKeyContentRevision]!.unsignedValue()
    let previous = try c[Self.cborKeyContentPreviousDigest]!.bytesValue()
    validity = try Validity(
      notBefore: c[Self.cborKeyContentNotBefore]!.unsignedValue(),
      expiresAt: c[Self.cborKeyContentExpiresAt]!.unsignedValue())
    fields = try ProfileFields(content: c)
    guard revision > 0, revision <= UInt64(Int64.max),
      previous.count == (revision == 1 ? 0 : 32)
    else { throw .invalidEncoding }
    previousDigest = revision == 1 ? nil : try Digest(bytes: previous)

    guard (1...Self.maximumDevices).contains(devices.count),
      Set(devices.map { $0.device }).count == devices.count
    else { throw .invalidEncoding }
    for certificate in devices {
      guard certificate.identityID == identityKey.id, certificate.generation == generation,
        !certificate.device.key.hasSameMaterial(as: identityKey.key)
      else { throw .identityMismatch }
    }
    guard let certificate = devices.first(where: { $0.device.id == signerID }) else {
      throw .deviceNotListed
    }
    guard validity.isWithin(certificate.validity) else { throw .invalidValidity }
    signer = certificate.device
    self.identityKey = identityKey
    self.devices = devices
    self.signedContent = signedContent
  }

  /// The canonical encoding.
  public var encoding: [UInt8] {
    CBOR.record(
      [
        Self.cborKeyTag: .text("Diem/profile"), Self.cborKeyVersion: .unsigned(4),
        Self.cborKeyIdentityKey: .bytes(identityKey.key.encoding),
        Self.cborKeyDevices: .array(devices.map { .bytes($0.encoding) }),
        Self.cborKeyContent: .bytes(signedContent.encoding),
      ], extensions: extensionFields
    ).encoded
  }

  static func sign(
    identityKey: IdentityPublicKey, devices: [DeviceCertificate], by signer: DevicePrivateKey,
    revision: UInt64, previousDigest: Digest?, validity: Validity, fields: ProfileFields
  ) async throws -> Self {
    guard let generation = devices.first?.generation else { throw DiemError.deviceNotListed }
    try fields.validate()
    let message = CBOR.record(
      [
        Self.cborKeyContentTag: .text("Diem/profile-content"),
        Self.cborKeyContentVersion: .unsigned(4),
        Self.cborKeyContentIdentityID: .bytes(identityKey.id.bytes),
        Self.cborKeyContentGeneration: .unsigned(generation),
        Self.cborKeyContentSignerID: .bytes(signer.publicKey.id.bytes),
        Self.cborKeyContentRevision: .unsigned(revision),
        Self.cborKeyContentPreviousDigest: .bytes(previousDigest?.bytes ?? []),
        Self.cborKeyContentNotBefore: .unsigned(validity.notBefore),
        Self.cborKeyContentExpiresAt: .unsigned(validity.expiresAt),
      ], extensions: fields.contentFields
    ).encoded
    return try Self(
      identityKey: identityKey, devices: devices,
      signedContent: await SignedMessage(signing: message, with: signer.key))
  }

  /// A content validity of `lifetime` from `now`, cut short at the signing certificate's
  /// expiry.
  static func contentValidity(for certificate: DeviceCertificate, at now: UInt64, lifetime: UInt64)
    throws -> Validity
  {
    let requested = try Validity(starting: now, lifetime: lifetime)
    let end = min(requested.expiresAt, certificate.validity.expiresAt)
    return try Validity(notBefore: now, expiresAt: end)
  }
}
