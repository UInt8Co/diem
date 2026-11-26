import DiemWeb
import JavaScriptKit

// The standalone runtime's generic ``ProfileRecord`` device link: grants carry arbitrary
// application fields and no application acceptance rules. Applications write their own
// forms over ``WebDeviceLink`` instead of linking these.

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
