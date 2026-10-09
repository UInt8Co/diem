/// An identity as one of its devices holds it: the current profile, this device's key and,
/// on devices that manage the device set, the identity private key.
///
/// A conforming type supplies that state. The operations are default implementations that
/// sign and return the next revision without storing it, so the conforming type decides
/// when to adopt it. ``BasicIdentity`` is the default identity, which adopts each revision
/// it publishes.
public protocol Identity<Profile>: Sendable {
  associatedtype Profile: Diem.Profile

  /// The current profile.
  var profile: Profile { get }
  var deviceKey: DevicePrivateKey { get }
  /// The identity private key, if this device holds it.
  var identityKey: IdentityPrivateKey? { get }
  var backend: any CryptoBackend { get }
  /// Lifetimes used when this identity publishes content or certifies devices.
  var profileLifetime: UInt64 { get }
  var deviceLifetime: UInt64 { get }
}

extension Identity {
  /// The identity ID.
  public var id: Digest { profile.id }

  /// The next revision, publishing `content`. With the identity key, expired device
  /// certificates are reissued first.
  public func updating(_ content: Profile.Content) async throws -> Profile {
    var devices = profile.devices
    if identityKey != nil, devices.contains(where: { !$0.validity.contains(backend.now) }) {
      devices = try await certify(devices.map { $0.device }, generation: profile.generation)
    }
    return try await publish(devices: devices, fields: Profile.fields(for: content))
  }

  /// The next revision, publishing the current fields with a fresh validity. With the
  /// identity key, every device certificate is also reissued.
  public func renewing() async throws -> Profile {
    var devices = profile.devices
    if identityKey != nil {
      devices = try await certify(devices.map { $0.device }, generation: profile.generation)
    }
    return try await publish(devices: devices, fields: profile.record.fields)
  }

  /// The next revision, certifying `device` in the current generation. Requires the
  /// identity key.
  public func adding(_ device: DevicePublicKey) async throws -> Profile {
    guard !device.key.hasSameMaterial(as: profile.identityKey.key) else {
      throw DiemError.identityMismatch
    }
    let keys = profile.devices.map { $0.device }.filter { $0 != device } + [device]
    let devices = try await certify(keys, generation: profile.generation)
    return try await publish(devices: devices, fields: profile.record.fields)
  }

  /// The next revision, removing the device with `id` by certifying the others in a new
  /// generation, which retires every older certificate. Requires the identity key.
  public func removing(_ id: Digest) async throws -> Profile {
    guard profile.device(id) != nil else { throw DiemError.deviceNotListed }
    guard id != deviceKey.publicKey.id else { throw DiemError.identityMismatch }
    let keys = profile.devices.map { $0.device }.filter { $0.id != id }
    let devices = try await certify(keys, generation: profile.generation + 1)
    return try await publish(devices: devices, fields: profile.record.fields)
  }

  /// A proof of `data` by this device for this identity.
  public func prove(_ data: [UInt8]) async throws -> ProofRecord {
    try await ProofRecord.sign(data, identityID: id, by: deviceKey)
  }

  private func certify(_ keys: [DevicePublicKey], generation: UInt64) async throws
    -> [DeviceCertificate]
  {
    guard let identityKey else { throw DiemError.identityKeyRequired }
    let validity = try Validity(starting: backend.now, lifetime: deviceLifetime)
    var devices: [DeviceCertificate] = []
    for key in keys {
      devices.append(
        try await .issue(by: identityKey, for: key, generation: generation, validity: validity))
    }
    return devices
  }

  private func publish(devices: [DeviceCertificate], fields: ProfileFields) async throws -> Profile {
    let now = backend.now
    // Expired certificates cannot act; listing them would make the profile unverifiable.
    let live = devices.filter { $0.validity.contains(now) }
    guard let certificate = live.first(where: { $0.device == deviceKey.publicKey }) else {
      throw devices.contains { $0.device == deviceKey.publicKey }
        ? DiemError.expired : DiemError.deviceNotListed
    }
    return try Profile(record: await ProfileRecord.sign(
      identityKey: profile.identityKey, devices: live, by: deviceKey,
      revision: profile.revision + 1, previousDigest: profile.digest,
      validity: ProfileRecord.contentValidity(for: certificate, at: now, lifetime: profileLifetime),
      fields: fields))
  }
}

/// The default ``Identity``: each operation publishes the next revision and adopts it as
/// the current profile.
public struct BasicIdentity<Profile: Diem.Profile>: Identity {
  /// The current profile. Each operation replaces it with a new signed revision.
  public private(set) var profile: Profile
  public let deviceKey: DevicePrivateKey
  public let identityKey: IdentityPrivateKey?
  public let backend: any CryptoBackend
  public let profileLifetime: UInt64
  public let deviceLifetime: UInt64

  /// Creates an identity whose only device is `deviceKey`, publishing `content` at
  /// revision 1.
  public init(
    _ content: Profile.Content, identityKey: IdentityPrivateKey, deviceKey: DevicePrivateKey,
    profileLifetime: UInt64 = ProfileRecord.defaultLifetime,
    deviceLifetime: UInt64 = DeviceCertificate.defaultLifetime,
    using backend: some CryptoBackend
  ) async throws {
    self.profile = try await Profile(
      publishing: content, identityKey: identityKey, deviceKey: deviceKey,
      profileLifetime: profileLifetime, deviceLifetime: deviceLifetime, using: backend)
    self.deviceKey = deviceKey
    self.identityKey = identityKey
    self.backend = backend
    self.profileLifetime = profileLifetime
    self.deviceLifetime = deviceLifetime
  }

  /// Creates an identity with new ML-DSA-65 software identity and device keys.
  public init(
    _ content: Profile.Content, profileLifetime: UInt64 = ProfileRecord.defaultLifetime,
    deviceLifetime: UInt64 = DeviceCertificate.defaultLifetime, using backend: some CryptoBackend
  ) async throws {
    try await self.init(
      content, identityKey: .generate(using: backend), deviceKey: .generate(using: backend),
      profileLifetime: profileLifetime, deviceLifetime: deviceLifetime, using: backend)
  }

  /// Opens an existing identity on a device that `profile` lists.
  public init(
    profile: Profile, deviceKey: DevicePrivateKey, identityKey: IdentityPrivateKey? = nil,
    profileLifetime: UInt64 = ProfileRecord.defaultLifetime,
    deviceLifetime: UInt64 = DeviceCertificate.defaultLifetime,
    using backend: some CryptoBackend
  ) async throws {
    _ = try Validity(starting: backend.now, lifetime: profileLifetime)
    _ = try Validity(starting: backend.now, lifetime: deviceLifetime)
    try await profile.verify(using: backend, at: profile.validity.notBefore)
    guard profile.device(deviceKey.publicKey.id) != nil else { throw DiemError.deviceNotListed }
    if let identityKey, identityKey.publicKey != profile.identityKey {
      throw DiemError.identityMismatch
    }
    self.profile = profile
    self.deviceKey = deviceKey
    self.identityKey = identityKey
    self.backend = backend
    self.profileLifetime = profileLifetime
    self.deviceLifetime = deviceLifetime
  }

  /// Enrolls `device` in `profile` with a recovered identity key, as
  /// `Profile.enrolling(_:identityKey:profileLifetime:deviceLifetime:using:)`, and opens
  /// the identity on that device.
  public static func enrolling(
    _ device: DevicePrivateKey, in profile: Profile, identityKey: IdentityPrivateKey,
    profileLifetime: UInt64 = ProfileRecord.defaultLifetime,
    deviceLifetime: UInt64 = DeviceCertificate.defaultLifetime,
    using backend: some CryptoBackend
  ) async throws -> Self {
    let next = try await profile.enrolling(
      device, identityKey: identityKey, profileLifetime: profileLifetime,
      deviceLifetime: deviceLifetime, using: backend)
    return try await Self(profile: next, deviceKey: device, identityKey: identityKey,
      profileLifetime: profileLifetime, deviceLifetime: deviceLifetime, using: backend)
  }

  /// Publishes `content` as the next revision.
  @discardableResult
  public mutating func update(_ content: Profile.Content) async throws -> Profile {
    profile = try await updating(content)
    return profile
  }

  /// Publishes the current fields as the next revision with a fresh validity.
  @discardableResult
  public mutating func renew() async throws -> Profile {
    profile = try await renewing()
    return profile
  }

  /// Certifies `device` in the current generation. Requires the identity key.
  @discardableResult
  public mutating func add(_ device: DevicePublicKey) async throws -> Profile {
    profile = try await adding(device)
    return profile
  }

  /// Removes the device with `id` in a new generation. Requires the identity key.
  @discardableResult
  public mutating func remove(_ id: Digest) async throws -> Profile {
    profile = try await removing(id)
    return profile
  }
}
