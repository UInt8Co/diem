/// A request to an absolute HTTPS URL. The hosting client supplies only DNS authorities.
public struct HostingHTTPRequest: Sendable, Equatable {
  public enum Method: String, Sendable { case get = "GET", head = "HEAD", put = "PUT" }

  public let method: Method
  public let url: String
  public var headers: [String: String]
  public var body: [UInt8]?

  public init(method: Method, url: String, headers: [String: String] = [:], body: [UInt8]? = nil) {
    self.method = method
    self.url = url
    self.headers = headers
    self.body = body
  }
}

public struct HostingHTTPResponse: Sendable, Equatable {
  public let status: Int
  public let headers: [String: String]
  public let body: [UInt8]

  public init(status: Int, headers: [String: String] = [:], body: [UInt8] = []) {
    self.status = status
    self.headers = headers
    self.body = body
  }

  /// ASCII case-insensitive header lookup. Adapters must coalesce duplicate field names.
  public func header(_ name: String) -> String? {
    headers.first { asciiLowercase($0.key) == asciiLowercase(name) }?.value
  }
}

/// Adapters must never follow redirects or send cookies or credentials. Apply a timeout,
/// bound response bytes while receiving them, and propagate task cancellation.
public protocol HostingHTTPClient: Sendable {
  func send(_ request: HostingHTTPRequest) async throws -> HostingHTTPResponse
}

func asciiLowercase(_ text: String) -> String {
  String(decoding: text.utf8.map { (65...90).contains($0) ? $0 + 32 : $0 }, as: UTF8.self)
}
