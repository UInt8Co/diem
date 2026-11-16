#if ProfileHostingServer
import ArgumentParser
import DiemProfileHosting
import Foundation
import Logging

@main
struct DiemProfileHostingServer: AsyncParsableCommand {
  static let configuration = CommandConfiguration(commandName: "diem-profile-hosting",
    abstract: "Serve signed Diem profiles behind a TLS-terminating proxy.")

  @Option(help: "Profile hosting JSON configuration file.") var config: String
  @Option(help: "Listener address.") var host = "127.0.0.1"
  @Option(help: "Listener port.") var port = 8080
  @Option(help: "Directory for the hosting SQLite database.") var dataDir = "data"
  @Option(name: .customLong("profile-alias"),
    help: "A further path that serves and accepts hosted profiles (repeatable).")
  var profileAliases: [String] = []

  func validate() throws {
    guard (1...65535).contains(port) else { throw ValidationError("port must be between 1 and 65535") }
  }

  func run() async throws {
    LoggingSystem.bootstrap(StreamLogHandler.standardError(label:))
    let logger = Logger(label: "diem-profile-hosting")
    let configuration = try JSONDecoder().decode(DiemProfileHostingConfiguration.self,
      from: Data(contentsOf: URL(fileURLWithPath: config)))
    try FileManager.default.createDirectory(atPath: dataDir, withIntermediateDirectories: true)
    let hosting = try await DiemProfileHosting(configuration: configuration,
      databasePath: configuration.databasePath(relativeTo: dataDir), profileAliases: profileAliases)
    logger.info("Hosting Diem profiles", metadata: ["domain": "\(configuration.domain)"])
    try await hosting.run(host: host, port: port, logger: logger)
  }
}
#else
#if canImport(Glibc)
  import Glibc
#elseif canImport(Musl)
  import Musl
#elseif canImport(Darwin)
  import Darwin
#endif

@main
enum DiemProfileHostingServer {
  static func main() {
    let message = "diem-profile-hosting was built without the ProfileHostingServer trait; "
      + "build it with `swift build --traits ProfileHostingServer`.\n"
    _ = message.withCString { write(2, $0, strlen($0)) }
    exit(1)
  }
}
#endif
