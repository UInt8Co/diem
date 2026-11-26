import Diem
import JavaScriptKit

/// Device linking in a disposable WASM instance: the joining device begins a session and
/// opens the response; the approving device inspects and responds. Applications supply
/// the profile type, their acceptance rules and their grant fields. The `@JS` functions
/// below are the generic ``ProfileRecord`` forms.
public enum WebDeviceLink {
  private struct Session {
    let request: DeviceLinkRequest
    let code: DeviceLinkCode
    let recipient: EncryptionPrivateKey
    let backend: BrowserBackend
  }

  // Each linking instance owns its HPKE recipient and one session.
  nonisolated(unsafe) private static var sessions: [String: Session] = [:]

  /// The QR code's request, after checking that `parameter` names exactly `request`.
  public static func inspect(parameter: String, request: [UInt8]) throws -> (DeviceLinkCode, DeviceLinkRequest) {
    let code = try DeviceLinkCode(parameter: parameter)
    guard code.matches(request) else { throw DiemError.invalidDeviceLink }
    return (code, try DeviceLinkRequest(encoding: request))
  }

  /// Requests a link for the backend's P-256 device with a fresh P-256 HPKE recipient.
  public static func begin(label: String, crypto: JSObject) async throws -> DeviceLinkBeginning {
    let backend = BrowserBackend(now: 0, crypto: crypto)
    let device = try DevicePublicKey(PublicKey(purpose: .device, algorithm: .p256,
      rawRepresentation: bytes(crypto.publicKey!("device"))))
    let recipient = try await backend.makeEncryptionKey(.p256)
    let request = try DeviceLinkRequest(device: device, recipient: recipient.publicKey,
      label: label, verifies: [.ed25519, .p256])
    let code = try DeviceLinkCode(request: request, using: backend)
    let session = Digest(hashing: backend.randomBytes(count: 32)).description
    sessions[session] = Session(request: request, code: code, recipient: recipient, backend: backend)
    return DeviceLinkBeginning(request: request.encoding, parameter: code.parameter, session: session)
  }

  /// Ends `session` and opens its response as `P`, verified at `now` and accepted by
  /// `accept`. The session ends whether or not opening succeeds.
  public static func open<P: DomainNamedProfile>(session: String, response: [UInt8], now: Double,
    as type: P.Type, accept: (P, DeviceLinkGrant) throws -> Void) async throws -> DeviceLinkResponse.Opened<P> {
    guard let state = sessions.removeValue(forKey: session), let time = seconds(now) else {
      throw DiemError.invalidDeviceLink
    }
    return try await DeviceLinkResponse.open(response, as: type, recipientKey: state.recipient,
      request: state.request, code: state.code, at: time, using: state.backend, accept: accept)
  }

  /// Seals a grant of `profile` at `domain` for the request the QR `code` names, after the
  /// grant verifies as `P` at `now` and passes `accept`. A `seed` transfers custody of the
  /// identity; it must derive the profile's identity key.
  public static func respond<P: DomainNamedProfile>(code parameter: String, request requestBytes: [UInt8],
    profile encoding: [UInt8], domain: String, seed: [UInt8]?, applications: [ApplicationID: CBOR],
    now: Double, crypto: JSObject, as type: P.Type, accept: (P, DeviceLinkGrant) throws -> Void) async throws -> [UInt8] {
    let (code, request) = try inspect(parameter: parameter, request: requestBytes)
    guard let time = seconds(now) else { throw DiemError.invalidDeviceLink }
    let backend = BrowserBackend(now: time, crypto: crypto)
    let profile = try P(encoding: encoding)
    try request.requireCompatible(identityKey: profile.identityKey, device: profile.signer)
    let sealed = try await seed.map { try IdentitySeed(entropy: $0) }?
      .sealed(to: request.recipient, identity: profile.identityKey, using: backend)
    let grant = try DeviceLinkGrant(profile: encoding, domain: DomainName(domain), seed: sealed,
      applications: applications)
    return try await DeviceLinkResponse.seal(grant, as: type, for: request, code: code,
      using: backend, accept: accept)
  }

  /// Releases a session's recipient key without opening a response.
  public static func destroy(session: String) {
    sessions.removeValue(forKey: session)
  }
}

@JS public struct DeviceLinkInspection {
  public let device: [UInt8]
  public let label: String
  public let verifies: [Double]

  public init(device: [UInt8], label: String, verifies: [Double]) {
    self.device = device; self.label = label; self.verifies = verifies
  }
}

/// Checks the QR digest before decoding the public request.
@JS public func inspectDeviceLink(parameter: String, request: [UInt8]) throws(JSException) -> DeviceLinkInspection {
  do {
    let (_, request) = try WebDeviceLink.inspect(parameter: parameter, request: request)
    return DeviceLinkInspection(device: request.device.key.encoding, label: request.label,
      verifies: request.verifies.map { Double($0.rawValue) })
  } catch { throw JSException(message: bridgeError(error)) }
}

@JS public struct DeviceLinkBeginning {
  public let request: [UInt8]
  public let parameter: String
  public let session: String

  public init(request: [UInt8], parameter: String, session: String) {
    self.request = request; self.parameter = parameter; self.session = session
  }
}

@JS public func destroyDeviceLink(session: String) {
  WebDeviceLink.destroy(session: session)
}

@JS public func beginDeviceLink(label: String, crypto: JSObject) async throws(JSException) -> DeviceLinkBeginning {
  do { return try await WebDeviceLink.begin(label: label, crypto: crypto) }
  catch { throw JSException(message: bridgeError(error)) }
}

/// An opened grant. `applications` are the grant's application fields.
@JS public struct DiemDeviceLinkOpening {
  public let profile: [UInt8]
  public let domain: String
  public let seed: [UInt8]?
  public let applications: [DiemApplicationField]

  public init(profile: [UInt8], domain: String, seed: [UInt8]?, applications: [DiemApplicationField]) {
    self.profile = profile; self.domain = domain; self.seed = seed; self.applications = applications
  }
}

/// Opens a response with no application acceptance rules.
@JS public func openDiemDeviceLink(session: String, response: [UInt8], now: Double)
  async throws(JSException) -> DiemDeviceLinkOpening {
  do {
    let opened = try await WebDeviceLink.open(session: session, response: response, now: now,
      as: ProfileRecord.self) { _, _ in }
    return DiemDeviceLinkOpening(profile: opened.grant.profile, domain: opened.grant.domain.name,
      seed: opened.seed?.entropy, applications: DiemApplicationField.list(opened.grant.applications))
  } catch { throw JSException(message: bridgeError(error)) }
}

@JS public struct DiemDeviceLinkApproval {
  public let code: String
  public let request: [UInt8]
  public let profile: [UInt8]
  public let domain: String
  public let seed: [UInt8]?
  public let applications: [DiemApplicationField]
  public let now: Double

  public init(code: String, request: [UInt8], profile: [UInt8], domain: String,
    seed: [UInt8]?, applications: [DiemApplicationField], now: Double) {
    self.code = code; self.request = request; self.profile = profile; self.domain = domain
    self.seed = seed; self.applications = applications; self.now = now
  }
}

/// Responds with a grant carrying the given application fields, with no application
/// acceptance rules.
@JS public func respondToDiemDeviceLink(input: DiemDeviceLinkApproval, crypto: JSObject)
  async throws(JSException) -> [UInt8] {
  do {
    return try await WebDeviceLink.respond(code: input.code, request: input.request,
      profile: input.profile, domain: input.domain, seed: input.seed,
      applications: DiemApplicationField.fields(input.applications), now: input.now,
      crypto: crypto, as: ProfileRecord.self) { _, _ in }
  } catch { throw JSException(message: bridgeError(error)) }
}
