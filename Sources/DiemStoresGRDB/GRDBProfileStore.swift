import Diem
import DiemStores
import Foundation
import GRDB

/// A GRDB-backed ``/DiemStores/ProfileStore`` that persists ``/Diem/Profile`` values in SQLite.
///
/// Profiles are stored as CBOR-encoded blobs in a `profiles` table. A secondary
/// `profile_keys` table maps every ``/Diem/PublicKeyEntry/id`` to its owning profile,
/// enabling O(1) ``profile(forKeyID:)`` lookups without a full table scan.
///
/// Both tables are created and migrated automatically.
public final class GRDBProfileStore: ProfileStore, @unchecked Sendable {
  private let db: DatabaseQueue

  public init(dbQueue: DatabaseQueue) throws {
    self.db = dbQueue
    try GRDBProfileStore.migrate(dbQueue)
  }

  // MARK: - Schema migrations

  private static func migrate(_ dbQueue: DatabaseQueue) throws {
    var migrator = DatabaseMigrator()

    migrator.registerMigration("v1") { db in
      try db.create(table: "profiles", ifNotExists: true) { t in
        t.column("id", .blob).primaryKey()
        t.column("cbor_data", .blob).notNull()
      }
      try db.create(table: "profile_keys", ifNotExists: true) { t in
        t.column("key_id", .blob).primaryKey()
        t.column("profile_id", .blob).notNull()
          .references("profiles", column: "id", onDelete: .cascade)
      }
      try db.create(indexOn: "profile_keys", columns: ["profile_id"])
    }

    try migrator.migrate(dbQueue)
  }

  // MARK: - ProfileStore

  public func store(_ profile: Profile) throws {
    let id = Data(profile.id)
    let cborData = Data(profile.encode())
    do {
      try db.write { db in
        try db.execute(
          sql: "INSERT INTO profiles (id, cbor_data) VALUES (?, ?)",
          arguments: [id, cborData])
        try insertKeys(for: profile, db: db)
      }
    } catch let error as DatabaseError where error.resultCode == .SQLITE_CONSTRAINT {
      throw DiemError.alreadyExists
    }
  }

  public func update(_ profile: Profile) throws -> ProfileUpdateSummary? {
    let existing = try self.profile(for: profile.id)
    guard let existing else { return nil }
    let id = Data(profile.id)
    let cborData = Data(profile.encode())
    try db.write { db in
      try db.execute(
        sql: "UPDATE profiles SET cbor_data = ? WHERE id = ?",
        arguments: [cborData, id])
      // Re-build key index (ON DELETE CASCADE handles old entries via profile delete,
      // but here we're updating in place so delete/re-insert manually).
      try db.execute(
        sql: "DELETE FROM profile_keys WHERE profile_id = ?",
        arguments: [id])
      try insertKeys(for: profile, db: db)
    }
    return ProfileUpdateSummary.diff(old: existing, new: profile)
  }

  public func profile(for id: [UInt8]) throws -> Profile? {
    let idData = Data(id)
    let row = try db.read { db in
      try Row.fetchOne(
        db, sql: "SELECT cbor_data FROM profiles WHERE id = ?", arguments: [idData])
    }
    guard let row else { return nil }
    let data: Data = row["cbor_data"]
    return try Profile.decode([UInt8](data))
  }

  /// Efficient key-ID lookup via the `profile_keys` index table.
  public func profile(forKeyID keyID: [UInt8]) throws -> Profile? {
    let keyData = Data(keyID)
    let row = try db.read { db in
      try Row.fetchOne(
        db,
        sql: """
          SELECT p.cbor_data
          FROM profiles p
          JOIN profile_keys pk ON pk.profile_id = p.id
          WHERE pk.key_id = ?
          """,
        arguments: [keyData])
    }
    guard let row else { return nil }
    let data: Data = row["cbor_data"]
    return try Profile.decode([UInt8](data))
  }

  public func allProfiles() throws -> [Profile] {
    let rows = try db.read { db in
      try Row.fetchAll(db, sql: "SELECT cbor_data FROM profiles")
    }
    return try rows.map { row in
      let data: Data = row["cbor_data"]
      return try Profile.decode([UInt8](data))
    }
  }

  public func remove(id: [UInt8]) throws {
    let idData = Data(id)
    // ON DELETE CASCADE removes profile_keys rows automatically.
    try db.write { db in
      try db.execute(sql: "DELETE FROM profiles WHERE id = ?", arguments: [idData])
    }
  }

  // MARK: - Helpers

  private func insertKeys(for profile: Profile, db: Database) throws {
    let profileID = Data(profile.id)
    for key in profile.keys {
      let keyID = Data(key.id)
      try db.execute(
        sql: "INSERT OR REPLACE INTO profile_keys (key_id, profile_id) VALUES (?, ?)",
        arguments: [keyID, profileID])
    }
  }
}
