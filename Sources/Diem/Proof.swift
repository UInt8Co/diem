/// A device's signed statement of data on behalf of an identity: a signed
/// ``ProofRecord`` and whatever the application decodes from its data.
///
/// A conforming type decodes its statement from a record. Encoding and verification have
/// default implementations. ``ProofRecord`` is the default proof, with uninterpreted data.
public protocol Proof: Hashable, Sendable {
  /// The signed record.
  var record: ProofRecord { get }
  /// Decodes and validates the data of a well-formed record.
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
  /// The signed data.
  public var data: [UInt8] { record.data }

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

/// The signed record behind every proof.
public struct ProofRecord: Proof {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyIdentityID: UInt64 = 2
  public static let cborKeyDeviceID: UInt64 = 3
  public static let cborKeyData: UInt64 = 4

  /// The device's signed message.
  public let signedMessage: SignedMessage
  public let identityID: Digest
  public let deviceID: Digest
  public let data: [UInt8]

  public var record: ProofRecord { self }
  public init(record: ProofRecord) { self = record }

  /// Decodes a proof from the device's signed message.
  public init(_ signedMessage: SignedMessage) throws(DiemError) {
    let a = try CBOR(decoding: signedMessage.message).recordValue(
      requiredKeys: Self.cborKeyTag..<(Self.cborKeyData + 1))
    guard a[Self.cborKeyTag]! == .text("Diem/proof"), a[Self.cborKeyVersion]! == .unsigned(3) else {
      throw .invalidEncoding
    }
    identityID = try Digest(bytes: a[Self.cborKeyIdentityID]!.bytesValue())
    deviceID = try Digest(bytes: a[Self.cborKeyDeviceID]!.bytesValue())
    data = try a[Self.cborKeyData]!.bytesValue()
    self.signedMessage = signedMessage
  }

  /// Decodes a proof from its encoding.
  public init(encoding: [UInt8]) throws(DiemError) {
    try self.init(SignedMessage(encoding: encoding))
  }

  static func sign(_ data: [UInt8], identityID: Digest, by device: DevicePrivateKey) async throws
    -> Self
  {
    let message = CBOR.record([
      Self.cborKeyTag: .text("Diem/proof"), Self.cborKeyVersion: .unsigned(3),
      Self.cborKeyIdentityID: .bytes(identityID.bytes),
      Self.cborKeyDeviceID: .bytes(device.publicKey.id.bytes), Self.cborKeyData: .bytes(data),
    ]).encoded
    return try Self(await SignedMessage(signing: message, with: device.key))
  }
}
