#if ProfileHostingServer
@testable import DiemProfileHosting
import HTTPTypes
import HummingbirdTesting
import Testing

@Suite struct StandaloneHostingTests {
  @Test func standaloneApplication() async throws {
    let hosting = try await DiemProfileHosting(configuration: .init(domain: "id.example"), databasePath: ":memory:")
    defer { await hosting.shutdown() }
    try await hosting.application().test(.live) { running in
      try await TestClient.withClient(host: "localhost", port: #require(running.port)) { client in
        let policy = try await client.execute(.init("/.well-known/diem/hosting", method: .get, authority: "id.example"))
        #expect(policy.status == .ok)
        let missing = try await client.execute(.init(DiemProfileHosting.profilePath, method: .get, authority: "alice.id.example"))
        #expect(missing.status == .notFound)
        let alias = try await client.execute(.init("/.well-known/example/profile.cbor", method: .get, authority: "alice.id.example"))
        #expect(alias.status == .notFound)
        for domain in ["id.example", "alice.id.example", "dc.example"] {
          let response = try await client.execute(.init("/admin", method: .get, authority: domain))
          #expect(response.status == .notFound)
        }
      }
    }
  }

  @Test func hostingStoreBoundsLockWait() async throws {
    let database = try await HostingDatabase(path: ":memory:")
    defer { await database.shutdown() }
    let timeout = try await database.busyTimeoutMilliseconds()
    #expect(timeout == 5000)
  }

  @Test func refusesAliasesInsideTheHostingAPI() async throws {
    for alias in ["relative.cbor", "/.well-known/diem/hosting/names/x"] {
      await #expect(throws: ConfigurationError.self) {
        _ = try await DiemProfileHosting(configuration: .init(domain: "id.example"), databasePath: ":memory:",
          profileAliases: [alias])
      }
    }
  }
}
#endif
