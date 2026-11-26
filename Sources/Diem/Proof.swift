/// A device's signed statement of one application's value on behalf of an identity: a
/// signed ``ProofRecord`` and whatever the application decodes from it.
///
/// A conforming type decodes its statement from a record. Encoding and verification have
/// default implementations. ``ProofRecord`` is the default proof, with an uninterpreted
/// value; ``StatementProof`` decodes a ``Statement``.
public protocol Proof: Hashable, Sendable {
  /// The signed record.
  var record: ProofRecord { get }
  /// Decodes and validates the value of a well-formed record.
  init(record: ProofRecord) throws
}

extension Proof {
  /// Decodes a proof from its ``encoding``.
  public init(encoding: [UInt8]) throws {
    try self.init(record: ProofRecord(encoding: encoding))
  }

  /// The canonical encoding.
  public var encoding: [UInt8] { record.signedMessage.encoding }
  public var identityID: Digest { record.identityID }
  public var deviceID: Digest { record.deviceID }
  /// The application whose value the device signed.
  public var application: ApplicationID { record.application }
  /// The signed value.
  public var value: CBOR { record.value }

  /// Verifies `profile`, then that its identity and one of its devices signed this proof.
  public func verify(
    against profile: some Profile, using backend: some CryptoBackend, at time: UInt64? = nil
  ) async throws {
    try await profile.verify(using: backend, at: time)
    guard record.identityID == profile.id else { throw DiemError.identityMismatch }
    guard let device = profile.device(record.deviceID) else { throw DiemError.deviceNotListed }
    try await record.signedMessage.verify(by: device.key, using: backend)
  }
}

/// The signed record behind every proof: an identity, a device and exactly one
/// application's value, under that application's ID.
public struct ProofRecord: Proof {
  /// CBOR field keys. Keys above ``cborKeyDeviceID`` are reserved for Diem.
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyIdentityID: UInt64 = 2
  public static let cborKeyDeviceID: UInt64 = 3

  /// The device's signed message.
  public let signedMessage: SignedMessage
  public let identityID: Digest
  public let deviceID: Digest
  public let application: ApplicationID
  public let value: CBOR

  public var record: ProofRecord { self }
  public init(record: ProofRecord) { self = record }

  /// Decodes a proof from the device's signed message.
  public init(_ signedMessage: SignedMessage) throws(DiemError) {
    let a = try CBOR(decoding: signedMessage.message).recordValue(
      tag: .text("Diem/proof"), version: 4,
      requiredKeys: Self.cborKeyTag..<(Self.cborKeyDeviceID + 1))
    guard a.applications.count == 1, let (application, value) = a.applications.first else {
      throw .invalidEncoding
    }
    identityID = try Digest(bytes: a[Self.cborKeyIdentityID]!.bytesValue())
    deviceID = try Digest(bytes: a[Self.cborKeyDeviceID]!.bytesValue())
    self.application = application
    self.value = value
    self.signedMessage = signedMessage
  }

  /// Decodes a proof from its encoding.
  public init(encoding: [UInt8]) throws(DiemError) {
    try self.init(SignedMessage(encoding: encoding))
  }

  static func sign(
    _ value: CBOR, for application: ApplicationID, identityID: Digest, by device: DevicePrivateKey
  ) async throws -> Self {
    let message = CBOR.record([
      Self.cborKeyTag: .text("Diem/proof"), Self.cborKeyVersion: .unsigned(4),
      Self.cborKeyIdentityID: .bytes(identityID.bytes),
      Self.cborKeyDeviceID: .bytes(device.publicKey.id.bytes),
    ], applications: [application: value]).encoded
    return try Self(await SignedMessage(signing: message, with: device.key))
  }
}

/// An application's value that a device signs as a ``StatementProof``.
///
/// The application decodes and encodes its own value; Diem carries it under
/// ``application`` in the ``ProofRecord``. Applications that check a statement before
/// signing it do so in their own `prove` operation and then call
/// `Identity.prove(_:)`.
public protocol Statement: Hashable, Sendable {
  /// The application whose field carries this statement.
  static var application: ApplicationID { get }
  /// Decodes a statement from its proof value.
  init(value: CBOR) throws
  /// The proof value.
  var value: CBOR { get }
}

/// A proof whose value is a ``Statement``.
public struct StatementProof<S: Statement>: Proof {
  public let record: ProofRecord
  public let statement: S

  /// Decodes the statement that `record` signs. A record of another application throws
  /// ``DiemError/invalidEncoding``.
  public init(record: ProofRecord) throws {
    guard record.application == S.application else { throw DiemError.invalidEncoding }
    self.record = record
    statement = try S(value: record.value)
  }
}

extension Identity {
  /// A proof of `value` for `application`, signed by this device for this identity.
  public func prove(_ value: CBOR, for application: ApplicationID) async throws -> ProofRecord {
    try await ProofRecord.sign(value, for: application, identityID: id, by: deviceKey)
  }

  /// A proof of `statement`, signed by this device for this identity. Diem does not
  /// check the statement first; applications that do wrap this call.
  public func prove<S: Statement>(_ statement: S) async throws -> StatementProof<S> {
    try StatementProof(record: await prove(statement.value, for: S.application))
  }

  /// Throws ``DiemError/expired`` unless the backend's current time is before
  /// `expiresAt` and at most `window` seconds before it: the signing-time check for a
  /// short-lived challenge.
  public func requireLive(until expiresAt: UInt64, window: UInt64) throws(DiemError) {
    let now = backend.now
    guard now < expiresAt, expiresAt - now <= window else { throw .expired }
  }
}
