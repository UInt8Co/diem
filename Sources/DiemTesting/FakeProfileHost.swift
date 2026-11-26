import Diem
import DiemProfileHostingClient
import Foundation

/// An in-memory profile host at `id.example` for tests of hosting clients.
///
/// It serves the hosting policy (with apex support), name status and profiles for child
/// names and the apex, and accepts publications under the hosting rules: identical
/// re-publication, increasing revisions, first-come claims and proof of work at ``bits``
/// leading zero bits. Its JSON, proof header and base64url handling are written
/// independently of the client's, so tests exercise the wire format rather than shared code.
public actor FakeProfileHost: HostingHTTPClient {
  public let domain = "id.example"
  /// Required leading zero bits for every new name.
  public private(set) var bits = 4
  /// Hosted profiles by wire label (`@` for the apex).
  public private(set) var claims: [String: ProfileRecord] = [:]
  /// The latest accepted revision of each identity.
  public private(set) var revisions: [Digest: ProfileRecord] = [:]
  /// Every request received, in order.
  public private(set) var requests: [HostingHTTPRequest] = []
  var limited = false
  var alwaysNeedsProof = false
  var omitBits = false
  var onlyMissing = false

  public init() {}

  /// `limited` answers every acceptable publication with `rate-limited`;
  /// `alwaysNeedsProof` refuses every publication with `proof-required`; `omitBits` leaves
  /// required bits out of refusals; `onlyMissing` waives the proof for `alice`; `bits` sets the required zero bits.
  public func configure(limited: Bool = false, alwaysNeedsProof: Bool = false,
    omitBits: Bool = false, onlyMissing: Bool = false, bits: Int = 4
  ) {
    self.bits = bits
    self.limited = limited
    self.alwaysNeedsProof = alwaysNeedsProof
    self.omitBits = omitBits
    self.onlyMissing = onlyMissing
  }

  public func send(_ request: HostingHTTPRequest) async throws -> HostingHTTPResponse {
    requests.append(request)
    let url = URL(string: request.url)!
    let host = url.host!
    let path = url.path
    if host == domain, request.method == .get {
      if path == "/.well-known/diem/hosting" {
        var policy = Self.policy()
        policy["apex"] = true
        return Self.json(policy)
      }
      let prefix = "/.well-known/diem/hosting/names/"
      if path.hasPrefix(prefix) {
        let label = String(path.dropFirst(prefix.count))
        return Self.json(["label": label,
          "status": label == "reserved" ? "invalid" : claims[label] == nil ? "available" : "claimed",
          "requiredBits": bits])
      }
    }
    guard host == domain || host.hasSuffix("." + domain),
      path == "/.well-known/diem/profile.cbor" else {
      return .init(status: 404)
    }
    let label = host == domain ? "@" : String(host.dropLast(domain.count + 1))
    guard !label.contains(".") else { return .init(status: 404) }
    if request.method == .get || request.method == .head {
      guard let profile = claims[label] else { return .init(status: 404) }
      return .init(status: 200, body: request.method == .head ? [] : profile.encoding)
    }
    let profile = try ProfileRecord(encoding: request.body ?? [])
    let names = profile.domains.map(\.name).filter { $0 == domain || $0.hasSuffix("." + domain) }
      .map { $0 == domain ? "@" : String($0.dropLast(domain.count + 1)) }
    guard names.contains(label) || (names.isEmpty && claims[label]?.id == profile.id) else {
      return problem("host-not-listed", status: 422)
    }
    if let previous = revisions[profile.id] {
      if previous == profile { return published(profile, names: names) }
      if previous.revision >= profile.revision { return problem("stale-revision", status: 409) }
    }
    let taken = names.filter { claims[$0] != nil && claims[$0]?.id != profile.id }
    if !taken.isEmpty { return problem("name-taken", status: 409, labels: taken) }
    var proofs: [String: [UInt8]] = [:]
    if let header = request.headers["Diem-Hosting-Proof"] {
      for entry in header.components(separatedBy: ", ") {
        let pair = entry.components(separatedBy: "=")
        guard pair.count == 2, proofs[pair[0]] == nil else {
          return problem("proof-required", status: 403, labels: names)
        }
        let value = pair[1].replacingOccurrences(of: "-", with: "+")
          .replacingOccurrences(of: "_", with: "/")
        guard let nonce = Data(base64Encoded: value + String(repeating: "=",
          count: (4 - value.count % 4) % 4)) else {
          return problem("proof-required", status: 403, labels: names)
        }
        proofs[pair[0]] = Array(nonce)
      }
    }
    let missing = names.filter { name in
      if claims[name]?.id == profile.id { return false }
      if onlyMissing && name == "alice" { return false }
      guard let nonce = proofs[name], (1...64).contains(nonce.count) else { return true }
      let input = Array("diem-profile-hosting-pow-v1\0id.example\0\(name)\0".utf8)
        + profile.id.bytes + nonce
      return SHA2.sha256(input)[0] >> (8 - bits) != 0
    }
    if !missing.isEmpty || alwaysNeedsProof {
      return problem("proof-required", status: 403, labels: missing.isEmpty ? names : missing)
    }
    if limited { return problem("rate-limited", status: 429) }
    claims = claims.filter { $0.value.id != profile.id }
    for name in names { claims[name] = profile }
    revisions[profile.id] = profile
    return published(profile, names: names)
  }

  func published(_ profile: ProfileRecord, names: [String]) -> HostingHTTPResponse {
    Self.json(["identity": Self.base64(profile.id.bytes), "revision": profile.revision,
      "domains": names.sorted().map { $0 == "@" ? domain : $0 + "." + domain }])
  }

  func problem(_ code: String, status: Int, labels: [String] = []) -> HostingHTTPResponse {
    Self.json(["type": "urn:diem:profile-hosting:" + code, "title": code,
      "status": status, "detail": "Refused", "labels": labels.map { label in
        var item: [String: Any] = ["label": label, "reason": code]
        if code == "proof-required" && !omitBits { item["requiredBits"] = bits }
        return item
      }], status: status, headers: status == 429 ? ["rEtRy-AfTeR": "37"] : [:])
  }

  /// Unpadded base64url through Foundation, independent of Diem's codec.
  public static func base64(_ bytes: [UInt8]) -> String {
    Data(bytes).base64EncodedString().replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
  }

  /// A JSON response with sorted keys.
  public static func json(_ object: [String: Any], status: Int = 200,
    headers: [String: String] = [:]
  ) -> HostingHTTPResponse {
    .init(status: status, headers: headers,
      body: Array(try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])))
  }

  /// A child-name hosting policy document.
  public static func policy(domain: String = "id.example", algorithm: String = "sha256-leading-zero-bits-v1",
    base: Int64 = 4, slope: Int64 = 0, length: Int64 = 8
  ) -> [String: Any] {
    ["domain": domain, "labelPattern": "[a-z0-9-]+", "maxClaimsPerIdentity": 3,
      "maxUpdatesPerIdentityPerHour": 12, "claimGraceAfterExpiry": 2_592_000,
      "proofOfWork": ["algorithm": algorithm, "baseBits": base,
        "bitsPerShorterCharacter": slope, "referenceLength": length]]
  }
}
