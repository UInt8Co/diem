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

/// Answers every request for the hosting domain or a name below it and passes others on.
/// The apex serves only the policy and name status; a deeper name is not found.
public struct ProfileHostingMiddleware<Context: RequestContext>: RouterMiddleware {
  private static var policyPath: String { "/.well-known/diem/hosting" }
  private static var namesPrefix: String { "/.well-known/diem/hosting/names/" }
  private let hosting: DiemProfileHosting
  private let domain: String

  public init(hosting: DiemProfileHosting) {
    self.hosting = hosting
    domain = hosting.configuration.domain
  }

  public func handle(_ request: Request, context: Context,
    next: (Request, Context) async throws -> Response
  ) async throws -> Response {
    guard let authority = request.head.authority,
      let host = DomainName(normalizing: String(authority.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)[0]))?.name,
      host == domain || host.hasSuffix("." + domain)
    else { return try await next(request, context) }
    let label = host == domain ? nil : String(host.dropLast(domain.count + 1))
    var response: Response
    do {
      response = try await route(request, label: label)
    } catch let problem as HostingProblem {
      response = try problem.response()
    } catch {
      context.logger.error("Profile hosting request failed: \(String(describing: error))")
      response = try HostingProblem(.busy, status: 503, detail: "The request could not be completed").response()
    }
    response.headers[.cacheControl] = "no-store"
    response.headers[.accessControlAllowOrigin] = "*"
    if request.method == .put { response.headers[.accessControlExposeHeaders] = "Retry-After" }
    if request.method == .head {
      if response.status == .ok { response.headers[.contentType] = "application/cbor" }
      response.body = .init()
    }
    return response
  }

  private func route(_ request: Request, label: String?) async throws -> Response {
    if label?.contains(".") == true { return Response(status: .notFound) }
    let path = request.uri.path
    if path == Self.policyPath {
      guard request.method == .get else { return Response(status: .notFound) }
      return try HostingJSON.response(hosting.policy)
    }
    if path.hasPrefix(Self.namesPrefix) {
      let name = path.dropFirst(Self.namesPrefix.count)
      guard request.method == .get, !name.isEmpty, !name.contains("/") else { return Response(status: .notFound) }
      return try HostingJSON.response(await hosting.name(String(name)))
    }
    guard let label, hosting.profilePaths.contains(path) else { return Response(status: .notFound) }
    switch request.method {
    case .get:
      guard let bytes = try await hosting.profile(label: label) else { return Response(status: .notFound) }
      return Response(status: .ok, headers: [.contentType: "application/cbor"],
        body: .init(byteBuffer: ByteBuffer(bytes: bytes)))
    case .head:
      return Response(status: try await hosting.hasProfile(label: label) ? .ok : .notFound)
    case .put:
      // Raw CBOR regardless of Content-Type.
      let bytes: ByteBuffer
      do { bytes = try await request.body.collect(upTo: CBOR.maximumBytes) }
      catch { throw HostingProblem(.tooLarge, status: 413, detail: "The request exceeds the CBOR byte limit") }
      let receipt = try await hosting.publish(Array(bytes.readableBytesView), label: label,
        proof: request.headers[HTTPField.Name("Diem-Hosting-Proof")!])
      return try HostingResponses.published(identity: receipt.identity, revision: receipt.revision,
        domains: receipt.domains)
    case .options:
      return Response(status: .noContent, headers: [.accessControlAllowMethods: "GET, HEAD, PUT",
        .accessControlAllowHeaders: "Content-Type, Diem-Hosting-Proof", .accessControlMaxAge: "600"])
    default:
      return Response(status: .notFound)
    }
  }
}
#endif
