#if ProfileHostingServer
import Diem
import DiemProfileHostingClient
import HTTPTypes
import Hummingbird
import NIOCore

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// The JSON documents that `DiemProfileHostingClient` parses.
enum HostingJSON {
  struct Policy: Encodable {
    struct ProofOfWork: Encodable {
      var algorithm = "sha256-leading-zero-bits-v1"
      let baseBits: Int
      let bitsPerShorterCharacter: Int
      let referenceLength: Int
    }

    let domain: String
    let labelPattern: String
    let maxClaimsPerIdentity: Int
    let maxUpdatesPerIdentityPerHour: Int
    let claimGraceAfterExpiry: Int
    let proofOfWork: ProofOfWork

    init(_ c: DiemProfileHostingConfiguration) {
      domain = c.domain
      labelPattern = c.labelPattern
      maxClaimsPerIdentity = c.maxClaimsPerIdentity
      maxUpdatesPerIdentityPerHour = c.maxUpdatesPerIdentityPerHour
      claimGraceAfterExpiry = c.claimGraceAfterExpiry
      proofOfWork = .init(baseBits: c.proofOfWork.baseBits,
        bitsPerShorterCharacter: c.proofOfWork.bitsPerShorterCharacter,
        referenceLength: c.proofOfWork.referenceLength)
    }
  }

  struct Name: Encodable {
    let label: String
    let status: String
    var requiredBits: Int? = nil
  }

  struct Published: Encodable {
    let identity: String
    let revision: UInt64
    let domains: [String]
  }

  struct Problem: Encodable {
    struct Label: Encodable {
      let label: String
      let reason: String
      let requiredBits: Int64?
    }

    let type: String
    let title: String
    let status: Int
    let detail: String
    let labels: [Label]?
  }

  static func response(_ body: some Encodable, status: HTTPResponse.Status = .ok,
    contentType: String = "application/json"
  ) throws -> Response {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return Response(status: status, headers: [.contentType: contentType],
      body: .init(byteBuffer: ByteBuffer(bytes: try encoder.encode(body))))
  }
}

/// Wire responses for hosts that also answer their own apex outside ``DiemProfileHosting``.
public enum HostingResponses {
  public static func claimedName(label: String) throws -> Response {
    try HostingJSON.response(HostingJSON.Name(label: label, status: "claimed"))
  }

  public static func published(identity: Data, revision: UInt64, domains: [String]) throws -> Response {
    try HostingJSON.response(HostingJSON.Published(identity: base64URL(identity), revision: revision,
      domains: domains))
  }
}

extension HostingProblem {
  /// The `application/problem+json` document, with Retry-After when the problem has one.
  public func response() throws -> Response {
    let body = HostingJSON.Problem(type: type, title: title, status: status, detail: detail,
      labels: labels.isEmpty ? nil : labels.map {
        .init(label: $0.label, reason: $0.reason, requiredBits: $0.requiredBits)
      })
    var response = try HostingJSON.response(body, status: .init(code: status),
      contentType: "application/problem+json")
    if let retryAfter { response.headers[.retryAfter] = String(retryAfter) }
    return response
  }
}

/// Proof header checks for hosts that accept publication of their own apex identity.
public enum HostingProofHeader {
  /// Throws `proof-required` for a malformed header; any well-formed one is accepted.
  public static func validateForApex(_ header: String?) throws {
    guard parseProof(header, limit: Int.max, allowApex: true) != nil else {
      throw HostingProblem(.proofRequired, status: 403, detail: "Supply a valid proof for each new name")
    }
  }
}

/// An absent header proves nothing; a malformed one is nil. Child-name hosts refuse `@`.
func parseProof(_ header: String?, limit: Int, allowApex: Bool = false) -> [String: [UInt8]]? {
  guard let header else { return [:] }
  guard let proofs = hostingProofs(fromHeader: header, limit: limit),
    allowApex || proofs["@"] == nil
  else { return nil }
  return proofs
}

func base64URL(_ bytes: some Sequence<UInt8>) -> String {
  Data(bytes).base64EncodedString().replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}
#endif
