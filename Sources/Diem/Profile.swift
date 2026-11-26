/// An identity's public statement: a signed ``ProfileRecord`` and the application
/// ``Content`` it carries.
///
/// A conforming type decodes and validates its content from a record, names the
/// ``applications`` whose fields that content owns, and says which ``ProfileFields``
/// publish new content. Keys, devices, revisions, encoding and verification have default
/// implementations. ``ProfileRecord`` is the default profile, whose content is its fields,
/// uninterpreted.
public protocol Profile: Hashable, Sendable {
  /// The application's view of the signed fields.
  associatedtype Content: Hashable, Sendable

  /// The application fields that ``Content`` owns. Publishing content replaces these
  /// fields and keeps every other application's.
  static var applications: Set<ApplicationID> { get }

  /// The signed record.
  var record: ProfileRecord { get }
  /// The content decoded from ``record``.
  var content: Content { get }

  /// Decodes and validates the content of a well-formed record. ``verify(using:at:)``
  /// checks its signatures and validity.
  init(record: ProfileRecord) throws
  /// The domains and owned application fields that publish `content`.
  static func fields(for content: Content) throws -> ProfileFields
  /// The complete signed fields that publish `content` over the `current` revision's.
  ///
  /// The default takes `current` (or no fields), replaces its domains, and sets or removes
  /// each field of ``applications`` from ``fields(for:)``. Other applications' fields and
  /// Diem fields this version does not know are kept verbatim. It throws
  /// ``DiemError/invalidEncoding`` if ``fields(for:)`` returns a field of an application
  /// outside ``applications``.
  static func fields(for content: Content, over current: ProfileFields?) throws -> ProfileFields
}

extension Profile {
  public static func fields(for content: Content, over current: ProfileFields?) throws
    -> ProfileFields
  {
    try (current ?? ProfileFields()).publishing(fields(for: content), owning: applications)
  }

  /// Decodes a well-formed profile from its ``encoding``.
  public init(encoding: [UInt8]) throws {
    try self.init(record: ProfileRecord(encoding: encoding))
  }

  /// Decodes a profile and verifies its certificates and signature at its own
  /// ``validity``'s start, so a profile that has since lapsed still verifies. Callers that
  /// need a current profile also check `validity.contains(now)`.
  public init(verifying encoding: [UInt8], using backend: some CryptoBackend) async throws {
    try self.init(encoding: encoding)
    try await verify(using: backend, at: validity.notBefore)
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
      fields: Self.fields(for: content, over: nil)))
  }

  /// The next revision, certifying `device` with a recovered identity key and signed by
  /// it. Removes `removedDevices` in the same revision, reissuing the final device set
  /// in a new generation when any are removed. The signing device cannot be removed.
  /// Publishes `content` if supplied, as `fields(for:over:)` over the current fields;
  /// otherwise preserves the current fields.
  ///
  /// The caller fetches this latest trusted profile and checks its monotonic version
  /// before recovery, then durably stores and publishes the result before using the
  /// new device.
  public func enrolling(
    _ device: DevicePrivateKey, identityKey: IdentityPrivateKey,
    removing removedDevices: Set<Digest> = [], publishing content: Content? = nil,
    profileLifetime: UInt64 = ProfileRecord.defaultLifetime,
    deviceLifetime: UInt64 = DeviceCertificate.defaultLifetime,
    using backend: some CryptoBackend
  ) async throws -> Self {
    try await verify(using: backend, at: validity.notBefore)
    guard identityKey.publicKey == self.identityKey,
      !device.publicKey.key.hasSameMaterial(as: identityKey.publicKey.key),
      !removedDevices.contains(device.publicKey.id)
    else { throw DiemError.identityMismatch }
    guard removedDevices.allSatisfy({ self.device($0) != nil }) else {
      throw DiemError.deviceNotListed
    }
    guard revision < UInt64(Int64.max),
      removedDevices.isEmpty || generation < UInt64(Int64.max)
    else { throw DiemError.invalidEncoding }
    let generation = generation + (removedDevices.isEmpty ? 0 : 1)
    let keys = devices.map { $0.device }.filter {
      !removedDevices.contains($0.id) && $0 != device.publicKey
    } + [device.publicKey]
    guard keys.count <= ProfileRecord.maximumDevices else { throw DiemError.invalidEncoding }
    let now = backend.now
    let validity = try Validity(starting: now, lifetime: deviceLifetime)
    let contentValidity = try Validity(starting: now, lifetime: profileLifetime)
    guard contentValidity.expiresAt <= validity.expiresAt else { throw DiemError.invalidValidity }
    let fields = try content.map { try Self.fields(for: $0, over: record.fields) } ?? record.fields
    var certificates: [DeviceCertificate] = []
    for key in keys {
      certificates.append(try await DeviceCertificate.issue(
        by: identityKey, for: key, generation: generation, validity: validity))
    }
    return try Self(record: await ProfileRecord.sign(
      identityKey: self.identityKey, devices: certificates, by: device,
      revision: revision + 1, previousDigest: digest, validity: contentValidity,
      fields: fields))
  }
}

/// A profile named by the domains that serve it. A verifier that fetched a profile from a
/// domain checks that the profile serves that domain.
///
/// Domains are a standard signed field of every ``ProfileRecord``. A conforming type
/// states how many it lists, checks them with ``validate(domains:)`` when decoding, and
/// says how its content lists other domains.
public protocol DomainNamedProfile: Profile {
  /// How many domains a profile of this type lists.
  static var domainCount: ClosedRange<Int> { get }
  /// `content` listing `domains` in that order, under this type's own naming rules.
  /// Hosting operations use it to add and remove hosted names.
  static func content(_ content: Content, replacingDomains domains: [DomainName]) throws
    -> Content
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
/// that serve it and each application's field.
///
/// Integer content keys are Diem's: 0–8 hold the content header, 9 the domains, and
/// higher keys are reserved for later Diem versions. Each application owns one field,
/// keyed by its ``ApplicationID``. Fields decoded from a profile keep any Diem keys above 9
/// that this version does not know, and re-signing the fields signs them unchanged.
public struct ProfileFields: Hashable, Sendable {
  /// The most domains one profile may list.
  public static let maximumDomains = 16
  /// The most application fields one profile may carry.
  public static let maximumApplications = 16

  /// Distinct domains.
  public var domains: [DomainName]
  /// Each application's field.
  public var applications: [ApplicationID: CBOR]
  /// Diem content keys above ``ProfileRecord/cborKeyContentDomains`` that this version
  /// does not know, kept from a decoded profile.
  var extensions: [UInt64: CBOR] = [:]

  public init(domains: [DomainName] = [], applications: [ApplicationID: CBOR] = [:]) {
    self.domains = domains
    self.applications = applications
  }

  /// Decodes caller-authored fields from their ``encoding``: the domains at
  /// ``ProfileRecord/cborKeyContentDomains`` and application fields. Any other integer
  /// key is ``DiemError/invalidEncoding``, because callers cannot author Diem fields.
  public init(encoding: [UInt8]) throws(DiemError) {
    let domains = ProfileRecord.cborKeyContentDomains
    let content = try CBOR(decoding: encoding).recordValue(requiredKeys: domains..<(domains + 1))
    guard content.fields.count == 1 else { throw .invalidEncoding }
    try self.init(content: content)
  }

  /// Decodes the fields of a profile content record.
  init(content: CBOR.Record) throws(DiemError) {
    var domains: [DomainName] = []
    for domain in try content[ProfileRecord.cborKeyContentDomains]!.arrayValue() {
      domains.append(try DomainName(domain.textValue()))
    }
    self.init(domains: domains, applications: content.applications)
    extensions = content.extensions(above: ProfileRecord.cborKeyContentDomains).fields
    try validate()
  }

  /// A CBOR map of the domains at ``ProfileRecord/cborKeyContentDomains`` and the
  /// application fields at their IDs, as in the signed content. Retained Diem extension
  /// keys are not part of it, so it always decodes with ``init(encoding:)``.
  public var encoding: [UInt8] {
    CBOR.record([ProfileRecord.cborKeyContentDomains: domainList], applications: applications)
      .encoded
  }

  var domainList: CBOR { .array(domains.map { .text($0.name) }) }

  /// These fields with `published`'s domains and, for each application in `owned`, its
  /// field from `published` (or none). Non-generic, so each profile type shares one copy.
  func publishing(_ published: ProfileFields, owning owned: Set<ApplicationID>)
    throws(DiemError) -> ProfileFields
  {
    guard published.applications.keys.allSatisfy(owned.contains) else { throw .invalidEncoding }
    var fields = self
    fields.domains = published.domains
    for application in owned {
      fields.applications[application] = published.applications[application]
    }
    return fields
  }

  /// Throws unless the domains are distinct and few enough, and the application fields
  /// are few enough.
  func validate() throws(DiemError) {
    guard domains.count <= Self.maximumDomains, Set(domains).count == domains.count else {
      throw .invalidDomain
    }
    guard applications.count <= Self.maximumApplications else { throw .invalidEncoding }
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

  /// CBOR field keys in the signed content. Keys above ``cborKeyContentDomains`` are
  /// reserved for Diem; application fields are keyed by ``ApplicationID``.
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

  private var extensionFields = CBOR.Record()

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
  /// The signed domains, application fields and retained Diem fields.
  public let fields: ProfileFields

  public var record: ProfileRecord { self }
  public var content: ProfileFields { fields }
  /// None: the content is the complete fields, so publishing it replaces every field.
  public static var applications: Set<ApplicationID> { [] }
  public init(record: ProfileRecord) { self = record }
  public static func fields(for content: ProfileFields) -> ProfileFields { content }
  /// `content` itself, including every application field and retained Diem field.
  public static func fields(for content: ProfileFields, over current: ProfileFields?)
    -> ProfileFields
  { content }
  /// `content` with `domains`, keeping its other fields.
  public static func content(_ content: ProfileFields, replacingDomains domains: [DomainName])
    -> ProfileFields
  {
    var content = content
    content.domains = domains
    return content
  }

  /// Decodes a well-formed profile from its encoding. ``verify(using:at:)`` checks its
  /// signatures and validity.
  public init(encoding: [UInt8]) throws(DiemError) {
    let a = try CBOR(decoding: encoding).recordValue(
      tag: .text("Diem/profile"), version: 5,
      requiredKeys: Self.cborKeyTag..<(Self.cborKeyContent + 1))
    let certificates = try a[Self.cborKeyDevices]!.arrayValue()
    var devices: [DeviceCertificate] = []
    for certificate in certificates {
      devices.append(try DeviceCertificate(encoding: certificate.bytesValue()))
    }
    try self.init(
      identityKey: IdentityPublicKey(PublicKey(encoding: a[Self.cborKeyIdentityKey]!.bytesValue())),
      devices: devices,
      signedContent: SignedMessage(encoding: a[Self.cborKeyContent]!.bytesValue()))
    extensionFields = a.extensions(above: Self.cborKeyContent)
  }

  private init(identityKey: IdentityPublicKey, devices: [DeviceCertificate], signedContent: SignedMessage)
    throws(DiemError)
  {
    let c = try CBOR(decoding: signedContent.message).recordValue(
      tag: .text("Diem/profile-content"), version: 5,
      requiredKeys: Self.cborKeyContentTag..<(Self.cborKeyContentDomains + 1))
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
        Self.cborKeyTag: .text("Diem/profile"), Self.cborKeyVersion: .unsigned(5),
        Self.cborKeyIdentityKey: .bytes(identityKey.key.encoding),
        Self.cborKeyDevices: .array(devices.map { .bytes($0.encoding) }),
        Self.cborKeyContent: .bytes(signedContent.encoding),
      ], retaining: extensionFields
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
        Self.cborKeyContentVersion: .unsigned(5),
        Self.cborKeyContentIdentityID: .bytes(identityKey.id.bytes),
        Self.cborKeyContentGeneration: .unsigned(generation),
        Self.cborKeyContentSignerID: .bytes(signer.publicKey.id.bytes),
        Self.cborKeyContentRevision: .unsigned(revision),
        Self.cborKeyContentPreviousDigest: .bytes(previousDigest?.bytes ?? []),
        Self.cborKeyContentNotBefore: .unsigned(validity.notBefore),
        Self.cborKeyContentExpiresAt: .unsigned(validity.expiresAt),
        Self.cborKeyContentDomains: fields.domainList,
      ], applications: fields.applications, extensions: fields.extensions
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
