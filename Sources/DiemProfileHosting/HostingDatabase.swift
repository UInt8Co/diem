#if ProfileHostingServer
import Diem
import DiemProfileHostingClient
import FluentKit
import FluentSQL
import FluentSQLiteDriver
import Logging
import NIOCore
import NIOPosix

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

actor HostingDatabase {
  private let eventLoop: any EventLoop
  private let databases: Databases
  private let logger = Logger(label: "diem.profile-hosting")
  private let ephemeralFile: String?
  private var closed = false

  init(path: String) async throws {
    eventLoop = MultiThreadedEventLoopGroup.singleton.next()
    databases = Databases(threadPool: .singleton, on: eventLoop)
    ephemeralFile = path == ":memory:"
      ? FileManager.default.temporaryDirectory.appendingPathComponent("diem-hosting-\(UUID()).sqlite").path : nil
    databases.use(.sqlite(.file(ephemeralFile ?? path)), as: .sqlite)
    let migrations = Migrations()
    migrations.add(CreateHostingTables())
    let migrator = Migrator(databases: databases, migrations: migrations, logger: logger, on: eventLoop)
    do {
      let sql = try database() as! any SQLDatabase
      // Bounded lock wait: sqlite-nio's default retries forever without sleeping.
      // The pool holds exactly one never-pruned connection, so one pragma covers
      // it; a pool that opens more must apply it to each.
      try await sql.raw("PRAGMA busy_timeout = 5000").run()
      try await sql.raw("PRAGMA journal_mode = WAL").run()
      try await sql.raw("PRAGMA synchronous = FULL").run()
      try await migrator.setupIfNeeded().get()
      try await migrator.prepareBatch().get()
    } catch {
      await databases.shutdownAsync()
      throw error
    }
  }

  /// The lock wait, in milliseconds, in force on the store's connection.
  func busyTimeoutMilliseconds() async throws -> Int? {
    try await (database() as! any SQLDatabase).raw("PRAGMA busy_timeout").first()?
      .decode(column: "timeout", as: Int.self)
  }

  /// Overwrites a stored profile's bytes verbatim, as a row another Diem version wrote
  /// would hold them. For tests.
  func overwriteEncoding(identity: Data, with encoding: Data) async throws {
    try await (database() as! any SQLDatabase).raw(
      "UPDATE hosting_profiles SET encoding = \(bind: encoding) WHERE identity = \(bind: identity)").run()
  }

  func shutdown() async {
    guard !closed else { return }
    closed = true
    await databases.shutdownAsync()
    removeEphemeralFile()
  }

  private nonisolated func removeEphemeralFile() {
    guard let ephemeralFile else { return }
    for suffix in ["", "-wal", "-shm", "-journal"] {
      try? FileManager.default.removeItem(atPath: ephemeralFile + suffix)
    }
  }

  deinit { removeEphemeralFile() }

  private func database() throws -> any Database {
    guard !closed, let db = databases.database(.sqlite, logger: logger, on: eventLoop) else {
      throw HostingProblem(.busy, status: 503, detail: "The hosting database is closed")
    }
    return db
  }

  func profile(label: String, now: UInt64, grace: Int) async throws -> Data? {
    guard let expiryFloor = Self.expiryFloor(now: now, grace: grace) else { return nil }
    let sql = try database() as! any SQLDatabase
    return try await sql.raw("""
      SELECT p.encoding FROM hosting_profiles p JOIN hosting_claims c ON c.identity = p.identity
      WHERE c.label = \(bind: label) AND p.expires >= \(bind: expiryFloor)
      """).first()?.decode(column: "encoding", as: Data.self)
  }

  func hasProfile(label: String, now: UInt64, grace: Int) async throws -> Bool {
    guard let expiryFloor = Self.expiryFloor(now: now, grace: grace) else { return false }
    let sql = try database() as! any SQLDatabase
    return try await sql.raw("""
      SELECT 1 FROM hosting_profiles p JOIN hosting_claims c ON c.identity = p.identity
      WHERE c.label = \(bind: label) AND p.expires >= \(bind: expiryFloor) LIMIT 1
      """).first() != nil
  }

  private static func expiryFloor(now: UInt64, grace: Int) -> Int64? {
    let threshold = now > UInt64(grace) ? now - UInt64(grace) : 0
    return Int64(exactly: threshold)
  }

  func publish(_ profile: ProfileRecord, label: String, proof: String?,
    configuration c: DiemProfileHostingConfiguration, now: UInt64
  ) async throws -> HostingReceipt {
    let suffix = "." + c.domain
    let labels = profile.domains.map(\.name).filter { $0.hasSuffix(suffix) }
      .map { String($0.dropLast(suffix.count)) }.sorted()
    guard profile.serves(label + suffix) || labels.isEmpty else {
      throw HostingProblem(.hostNotListed, status: 422, detail: "The profile does not list the request host")
    }
    let invalid = labels.filter { !c.validLabel($0) }
    guard invalid.isEmpty else {
      throw HostingProblem(.invalidLabel, status: 422, detail: "Hosted names must be valid single labels",
        // A deeper name has no single label to report; clients refuse non-label entries.
        labels: invalid.filter { c.normalizedLabel($0) == $0 }.map { .init(label: $0, reason: "invalid-label") })
    }
    guard labels.count <= c.maxClaimsPerIdentity else {
      throw HostingProblem(.tooManyClaims, status: 403, detail: "The profile exceeds the claim limit")
    }
    let identity = Data(profile.id.bytes)
    let encoding = Data(profile.encoding)
    let digest = Data(profile.digest.bytes)
    let expiryFloor = Int64(now > UInt64(c.claimGraceAfterExpiry) ? now - UInt64(c.claimGraceAfterExpiry) : 0)
    let answer = HostingReceipt(identity: identity, revision: profile.revision,
      domains: labels.map { $0 + suffix })
    // A fixed event-loop pool has one connection. IMMEDIATE also protects against
    // another process opening the same file; reads and writes share its snapshot.
    return try await database().withConnection { db in
      let sql = db as! any SQLDatabase
      try await sql.raw("BEGIN IMMEDIATE").run()
      do {
        let stale = try await sql.raw("SELECT identity FROM hosting_profiles WHERE expires < \(bind: expiryFloor) ORDER BY expires LIMIT 16").all()
        for row in stale {
          try await Self.purge(try row.decode(column: "identity", as: Data.self), on: sql)
        }
        // Targeted lookups reclaim needed names even when the bounded sweep has a backlog.
        for name in labels {
          if let row = try await sql.raw("""
            SELECT p.identity FROM hosting_profiles p JOIN hosting_claims c ON c.identity = p.identity
            WHERE c.label = \(bind: name) AND p.expires < \(bind: expiryFloor)
            """).first() {
            try await Self.purge(try row.decode(column: "identity", as: Data.self), on: sql)
          }
        }
        if let row = try await sql.raw("SELECT expires FROM hosting_profiles WHERE identity = \(bind: identity)").first(),
          try row.decode(column: "expires", as: Int64.self) < expiryFloor {
          try await Self.purge(identity, on: sql)
        }
        let held = try await sql.raw("SELECT label FROM hosting_claims WHERE identity = \(bind: identity)").all()
          .map { try $0.decode(column: "label", as: String.self) }
        guard profile.serves(label + suffix) || (labels.isEmpty && held.contains(label)) else {
          throw HostingProblem(.hostNotListed, status: 422, detail: "The profile does not list the request host")
        }
        if let row = try await sql.raw("SELECT revision, generation, digest, encoding FROM hosting_profiles WHERE identity = \(bind: identity)").first() {
          let stored = try row.decode(column: "encoding", as: Data.self)
          if try row.decode(column: "digest", as: Data.self) == digest, stored == encoding {
            try await sql.raw("COMMIT").run()
            return answer
          }
          let revision = UInt64(try row.decode(column: "revision", as: String.self))
          let generation = UInt64(try row.decode(column: "generation", as: String.self))
          let advances = revision.map { profile.revision > $0 } == true
            && generation.map { profile.generation >= $0 } == true
          // A stored encoding this Diem cannot decode sets no floor: the verified profile
          // of the same identity replaces it as a newer revision would.
          guard advances || (try? ProfileRecord(encoding: Array(stored))) == nil else {
            throw HostingProblem(.staleRevision, status: 409,
              detail: "Revision must increase and device generation must not decrease")
          }
        }
        var taken: [HostingProblem.Label] = []
        for name in labels {
          if let row = try await sql.raw("SELECT identity FROM hosting_claims WHERE label = \(bind: name)").first(),
            try row.decode(column: "identity", as: Data.self) != identity {
            taken.append(.init(label: name, reason: "name-taken"))
          }
        }
        guard taken.isEmpty else {
          throw HostingProblem(.nameTaken, status: 409, detail: "Names already held", labels: taken)
        }
        let proofs = parseProof(proof, limit: c.maxClaimsPerIdentity)
        let pow = c.proofOfWork
        let needed = labels.filter { !held.contains($0) && pow.requiredBits(label: $0) != 0 }
        let missing = needed.filter {
          !pow.isValid(nonce: proofs?[$0] ?? [], domain: c.domain, label: $0, identityID: profile.id)
        }
        guard proofs != nil, missing.isEmpty else {
          throw HostingProblem(.proofRequired, status: 403, detail: "Supply a valid proof for each new name",
            labels: (proofs == nil ? needed : missing).map {
              .init(label: $0, reason: "proof-required", requiredBits: pow.requiredBits(label: $0).map(Int64.init))
            })
        }
        let cutoff = Int64(now) - 3600
        try await sql.raw("DELETE FROM hosting_updates WHERE identity = \(bind: identity) AND accepted <= \(bind: cutoff)").run()
        let countRow = try await sql.raw("SELECT COUNT(*) AS count, MIN(accepted) AS oldest FROM hosting_updates WHERE identity = \(bind: identity)").first()!
        if try countRow.decode(column: "count", as: Int.self) >= c.maxUpdatesPerIdentityPerHour {
          let oldest = try countRow.decode(column: "oldest", as: Int64.self)
          throw HostingProblem(.rateLimited, status: 429, detail: "The hourly update limit has been reached",
            retryAfter: UInt64(max(1, 3600 - (Int64(now) - oldest))))
        }
        try await sql.raw("""
          INSERT INTO hosting_profiles (identity, revision, generation, expires, digest, encoding)
          VALUES (\(bind: identity), \(bind: String(profile.revision)), \(bind: String(profile.generation)),
            \(bind: Int64(clamping: profile.validity.expiresAt)), \(bind: digest), \(bind: encoding))
          ON CONFLICT(identity) DO UPDATE SET revision = excluded.revision, generation = excluded.generation,
            expires = excluded.expires, digest = excluded.digest, encoding = excluded.encoding
          """).run()
        try await sql.raw("DELETE FROM hosting_claims WHERE identity = \(bind: identity)").run()
        for name in labels {
          try await sql.raw("INSERT INTO hosting_claims (label, identity) VALUES (\(bind: name), \(bind: identity))").run()
        }
        try await sql.raw("INSERT INTO hosting_updates (identity, accepted) VALUES (\(bind: identity), \(bind: Int64(now)))").run()
        try await sql.raw("COMMIT").run()
        return answer
      } catch {
        do { try await sql.raw("ROLLBACK").run() } catch {
          self.logger.warning("hosting rollback failed: \(error)")
        }
        throw error
      }
    }
  }

  private static func purge(_ identity: Data, on sql: any SQLDatabase) async throws {
    try await sql.raw("DELETE FROM hosting_claims WHERE identity = \(bind: identity)").run()
    try await sql.raw("DELETE FROM hosting_updates WHERE identity = \(bind: identity)").run()
    try await sql.raw("DELETE FROM hosting_profiles WHERE identity = \(bind: identity)").run()
  }
}

struct CreateHostingTables: AsyncMigration {
  // Fluent records applied migrations by name; this one predates the move into diem.
  var name: String { "DiemProfileHosting.CreateHostingTables" }

  func prepare(on database: any Database) async throws {
    let sql = database as! any SQLDatabase
    try await sql.raw("""
      CREATE TABLE hosting_profiles (identity BLOB PRIMARY KEY NOT NULL CHECK(length(identity) = 32),
        revision TEXT NOT NULL, generation TEXT NOT NULL, expires INTEGER NOT NULL,
        digest BLOB NOT NULL, encoding BLOB NOT NULL)
      """).run()
    try await sql.raw("CREATE INDEX hosting_expiry ON hosting_profiles(expires)").run()
    try await sql.raw("CREATE TABLE hosting_claims (label TEXT PRIMARY KEY NOT NULL, identity BLOB NOT NULL REFERENCES hosting_profiles(identity))").run()
    try await sql.raw("CREATE INDEX hosting_holder ON hosting_claims(identity)").run()
    try await sql.raw("CREATE TABLE hosting_updates (identity BLOB NOT NULL REFERENCES hosting_profiles(identity), accepted INTEGER NOT NULL)").run()
    try await sql.raw("CREATE INDEX hosting_update_window ON hosting_updates(identity, accepted)").run()
  }

  func revert(on database: any Database) async throws {
    let sql = database as! any SQLDatabase
    for table in ["hosting_updates", "hosting_claims", "hosting_profiles"] {
      try await sql.raw("DROP TABLE \(ident: table)").run()
    }
  }
}
#endif
