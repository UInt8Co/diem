/// An RFC 9457 refusal: parsed by clients and thrown and rendered by hosts.
public struct HostingProblem: Error, Sendable, Equatable {
  // Not RawRepresentable: its generic == would equate `.unknown("busy")` with `.busy`.
  public enum Code: Sendable, Equatable {
    case invalidProfile, hostNotListed, invalidLabel, tooManyClaims, proofRequired
    case nameTaken, staleRevision, rateLimited, tooLarge, busy
    case unknown(String)

    /// The `<code>` in `urn:diem:profile-hosting:<code>`.
    public var rawValue: String {
      switch self {
      case .invalidProfile: "invalid-profile"
      case .hostNotListed: "host-not-listed"
      case .invalidLabel: "invalid-label"
      case .tooManyClaims: "too-many-claims"
      case .proofRequired: "proof-required"
      case .nameTaken: "name-taken"
      case .staleRevision: "stale-revision"
      case .rateLimited: "rate-limited"
      case .tooLarge: "too-large"
      case .busy: "busy"
      case .unknown(let value): value
      }
    }

    public init(_ value: String) {
      switch value {
      case "invalid-profile": self = .invalidProfile
      case "host-not-listed": self = .hostNotListed
      case "invalid-label": self = .invalidLabel
      case "too-many-claims": self = .tooManyClaims
      case "proof-required": self = .proofRequired
      case "name-taken": self = .nameTaken
      case "stale-revision": self = .staleRevision
      case "rate-limited": self = .rateLimited
      case "too-large": self = .tooLarge
      case "busy": self = .busy
      default: self = .unknown(value)
      }
    }
  }

  public struct Label: Sendable, Equatable {
    public let label: String
    public let reason: String
    public let requiredBits: Int64?

    public init(label: String, reason: String, requiredBits: Int64? = nil) {
      self.label = label
      self.reason = reason
      self.requiredBits = requiredBits
    }
  }

  public let type: String
  public let code: Code
  public let title: String
  public let status: Int
  public let detail: String
  public let labels: [Label]
  /// Seconds from the Retry-After header, when present and valid.
  public let retryAfter: UInt64?

  /// A refusal as a host sends it, typed `urn:diem:profile-hosting:<code>` and titled by its code.
  public init(_ code: Code, status: Int, detail: String, labels: [Label] = [],
    retryAfter: UInt64? = nil
  ) {
    self.code = code
    type = "urn:diem:profile-hosting:" + code.rawValue
    title = code.rawValue
    self.status = status
    self.detail = detail
    self.labels = labels
    self.retryAfter = retryAfter
  }

  public init(response: HostingHTTPResponse) throws(ProfileHostingError) {
    let fields = try JSON(response.body).object()
    type = try fields.field("type").string()
    let prefix = "urn:diem:profile-hosting:"
    guard type.hasPrefix(prefix), type.utf8.count > prefix.utf8.count else {
      throw .invalidResponse
    }
    code = Code(String(type.dropFirst(prefix.count)))
    title = try fields.field("title").string()
    detail = try fields.field("detail").string()
    guard try fields.field("status").integer() == Int64(response.status) else {
      throw .invalidResponse
    }
    status = response.status
    var parsed: [Label] = []
    if let value = fields["labels"] {
      for item in try value.array() {
        let label = try item.object()
        let wireLabel = try label.field("label").string()
        guard validWireLabel(wireLabel) else { throw .invalidResponse }
        parsed.append(try Label(label: wireLabel,
          reason: label.field("reason").string(), requiredBits: label["requiredBits"]?.integer()))
      }
    }
    labels = parsed
    if let header = response.header("Retry-After"), !header.isEmpty,
      header.utf8.allSatisfy({ (48...57).contains($0) }) {
      retryAfter = UInt64(header)
    } else { retryAfter = nil }
  }
}

public enum ProfileHostingError: Error, Sendable, Equatable {
  case cancelled
  case invalidResponse
  case unexpectedStatus(Int)
  case domainMismatch
  case unsupportedAlgorithm(String)
  case invalidLabel(String)
  case nameTaken(String)
  case unsolvable(String)
  case invalidProof(String)
  case noHostedName
  case hostNotListed
  case tooLarge
  case domainsMismatch
  case publishedMismatch
  case problem(HostingProblem)
}

func checkHostingCancellation() throws(ProfileHostingError) {
  if Task.isCancelled { throw .cancelled }
}
