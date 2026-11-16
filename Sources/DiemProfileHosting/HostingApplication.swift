#if ProfileHostingServer
import Hummingbird
import Logging

extension DiemProfileHosting {
  /// The standalone application serves only this module; every other route is 404.
  /// The caller owns the database and shuts it down after the application drains.
  public nonisolated func application(host: String = "127.0.0.1", port: Int = 8080,
    logger: Logger = Logger(label: "diem-profile-hosting")
  ) -> Application<RouterResponder<BasicRequestContext>> {
    let router = Router()
    router.middlewares.add(middleware())
    return Application(router: router,
      configuration: .init(address: .hostname(host, port: port), serverName: "diem-profile-hosting"),
      logger: logger)
  }

  /// SIGTERM/SIGINT drain the listener before closing the database, including on failure.
  public func run(host: String = "127.0.0.1", port: Int = 8080,
    logger: Logger = Logger(label: "diem-profile-hosting")
  ) async throws {
    defer { await shutdown() }
    try await application(host: host, port: port, logger: logger)
      .runService(gracefulShutdownSignals: [.sigterm, .sigint])
  }
}
#endif
