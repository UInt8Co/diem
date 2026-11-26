import Diem
import JavaScriptKit

/// One application's field: its reverse-DNS ID and the canonical CBOR encoding of its
/// value, which the application decodes itself.
@JS public struct DiemApplicationField {
  public let id: String
  public let value: [UInt8]

  public init(id: String, value: [UInt8]) { self.id = id; self.value = value }

  /// `fields` in ``ApplicationID`` order.
  public static func list(_ fields: [ApplicationID: CBOR]) -> [DiemApplicationField] {
    fields.keys.sorted().map { DiemApplicationField(id: $0.name, value: fields[$0]!.encoded) }
  }

  /// Decodes a list from JavaScript; an invalid ID, a repeated ID or a malformed value is
  /// ``DiemError/invalidEncoding``.
  public static func fields(_ list: [DiemApplicationField]) throws(DiemError) -> [ApplicationID: CBOR] {
    var fields: [ApplicationID: CBOR] = [:]
    for field in list {
      let id = try ApplicationID(field.id)
      guard fields[id] == nil else { throw .invalidEncoding }
      fields[id] = try CBOR(decoding: field.value)
    }
    return fields
  }
}

/// A certified device. Times are exact decimal strings.
@JS public struct DiemDeviceInfo {
  /// The device ID, lowercase hex.
  public let id: String
  /// The device's Diem public-key encoding.
  public let key: [UInt8]
  public let notBefore: String
  public let expiresAt: String

  public init(id: String, key: [UInt8], notBefore: String, expiresAt: String) {
    self.id = id; self.key = key; self.notBefore = notBefore; self.expiresAt = expiresAt
  }
}

/// The application-independent facts of a verified profile. IDs are lowercase hex; all
/// integers are exact decimal strings.
@JS public struct DiemProfileInfo {
  public let id: String
  public let generation: String
  public let revision: String
  public let notBefore: String
  public let expiresAt: String
  /// True when the time checked is before `notBefore` or at or after `expiresAt`.
  public let lapsed: Bool
  public let domains: [String]
  /// The ID of the device that signed this revision.
  public let signer: String
  public let devices: [DiemDeviceInfo]
  /// Every application field in the signed content, in ID order.
  public let applications: [DiemApplicationField]

  public init(id: String, generation: String, revision: String, notBefore: String,
    expiresAt: String, lapsed: Bool, domains: [String], signer: String,
    devices: [DiemDeviceInfo], applications: [DiemApplicationField]) {
    self.id = id; self.generation = generation; self.revision = revision
    self.notBefore = notBefore; self.expiresAt = expiresAt; self.lapsed = lapsed
    self.domains = domains; self.signer = signer; self.devices = devices
    self.applications = applications
  }

  /// The facts of `profile`, lapsed unless its validity contains `time`.
  public init(_ profile: some Profile, at time: UInt64) {
    let record = profile.record
    self.init(id: profile.id.description, generation: String(profile.generation),
      revision: String(profile.revision), notBefore: String(profile.validity.notBefore),
      expiresAt: String(profile.validity.expiresAt), lapsed: !profile.validity.contains(time),
      domains: record.domains.map { $0.name }, signer: profile.signer.id.description,
      devices: profile.devices.map { certificate in
        DiemDeviceInfo(id: certificate.device.id.description, key: certificate.device.key.encoding,
          notBefore: String(certificate.validity.notBefore),
          expiresAt: String(certificate.validity.expiresAt))
      },
      applications: DiemApplicationField.list(record.fields.applications))
  }
}

/// Verifies a stored public profile, including a lapsed one, without binding it to a
/// domain or requesting private keys: its certificates and signature must verify at its
/// own `notBefore`. Callers own identity pinning and generation/revision floors, and
/// decode the application fields they understand.
@JS public func verifyDiemProfile(encoding: [UInt8], now: Double,
  crypto: JSObject) async throws(JSException) -> DiemProfileInfo {
  do {
    guard let time = seconds(now) else { throw DiemError.invalidValidity }
    let profile = try await ProfileRecord(verifying: encoding,
      using: BrowserBackend(now: time, crypto: crypto))
    return DiemProfileInfo(profile, at: time)
  } catch {
    throw JSException(message: bridgeError(error))
  }
}
