@testable import Diem
import DiemTesting
import Testing

extension ApplicationID {
  static let notes = try! ApplicationID("org.example.notes")
}

/// A profile named by exactly one domain, with a note in its application's field.
private struct NoteProfile: DomainNamedProfile {
  struct Content: Hashable, Sendable {
    var domain: DomainName
    var note: String
  }

  static var domainCount: ClosedRange<Int> { 1...1 }
  static var applications: Set<ApplicationID> { [.notes] }

  let record: ProfileRecord
  let content: Content

  init(record: ProfileRecord) throws {
    try Self.validate(domains: record.fields.domains)
    guard let note = record.fields.applications[.notes] else { throw DiemError.invalidEncoding }
    self.record = record
    content = Content(domain: record.fields.domains[0], note: try note.textValue())
  }

  static func fields(for content: Content) throws -> ProfileFields {
    ProfileFields(domains: [content.domain], applications: [.notes: .text(content.note)])
  }

  static func content(_ content: Content, replacingDomains domains: [DomainName]) throws -> Content {
    try validate(domains: domains)
    return Content(domain: domains[0], note: content.note)
  }
}

/// A profile whose content claims to own the notes field but publishes another's.
private struct TrespassingProfile: Profile {
  static var applications: Set<ApplicationID> { [.notes] }
  let record: ProfileRecord
  var content: Int { 0 }
  init(record: ProfileRecord) { self.record = record }
  static func fields(for content: Int) -> ProfileFields { .data([1]) }
}

/// An identity that leaves adopting each revision to its caller.
private struct DraftIdentity: Identity {
  let profile: NoteProfile
  let deviceKey: DevicePrivateKey
  let identityKey: IdentityPrivateKey?
  let backend: any CryptoBackend
  var profileLifetime: UInt64 { ProfileRecord.defaultLifetime }
  var deviceLifetime: UInt64 { DeviceCertificate.defaultLifetime }
}

@Suite struct ProfileProtocolTests {
  let backend = TestBackend()

  @Test func domainNamesAreLowercaseDNSNames() throws {
    for name in ["alice", "Alice.example", "ali_ce.example", "-a.example", "a-.example", "a..example",
      "a.example.", "álîce.example", "alice.例え", "alice.💬", "a.\u{212A}",
      String(repeating: "a", count: 64) + ".example"] {
      #expect(throws: DiemError.invalidDomain) { try DomainName(name) }
    }
    #expect(try DomainName("a-1.example").name == "a-1.example")
    #expect(DomainName(normalizing: "Alice.Example")?.name == "alice.example")
    // Only ASCII folds; the Kelvin sign is not a "k".
    #expect(DomainName(normalizing: "a.\u{212A}") == nil)
  }

  @Test func domainsAreSignedAndChecked() async throws {
    let one = try DomainName("one.example"), two = try DomainName("two.example")
    var identity = try await TestIdentity(ProfileFields(domains: [one, two]), using: backend)
    let decoded = try ProfileRecord(encoding: identity.profile.encoding)
    #expect(decoded.domains == [one, two] && decoded.serves(two) && decoded.serves("one.example"))
    #expect(!decoded.serves("three.example"))

    await #expect(throws: DiemError.invalidDomain) {
      try await identity.update(ProfileFields(domains: [one, one]))
    }
    let many = try (0...ProfileFields.maximumDomains).map { try DomainName("d\($0).example") }
    await #expect(throws: DiemError.invalidDomain) {
      try await identity.update(ProfileFields(domains: many))
    }
    let tooMany = try (0...ProfileFields.maximumApplications).map {
      (try ApplicationID("org.example.app\($0)"), CBOR.null)
    }
    await #expect(throws: DiemError.invalidEncoding) {
      try await identity.update(ProfileFields(applications: Dictionary(uniqueKeysWithValues: tooMany)))
    }
    #expect(try await identity.renew().domains == [one, two])
  }

  @Test func fieldsEncodeAsTheirSignedContentKeys() throws {
    let fields = ProfileFields(domains: [try DomainName("one.example")], applications: [.test: .unsigned(1)])
    #expect(try CBOR(decoding: fields.encoding)
      == .map([.unsigned(9): .array([.text("one.example")]), .text("org.example.test"): .unsigned(1)]))
    #expect(try ProfileFields(encoding: fields.encoding) == fields)
    // Callers author only domains and application fields: every other integer key is Diem's.
    for key: UInt64 in [4, 10, 16] {
      #expect(throws: DiemError.invalidEncoding) {
        try ProfileFields(encoding: CBOR.record([9: .array([]), key: .null]).encoded)
      }
    }
    #expect(throws: DiemError.invalidEncoding) {
      try ProfileFields(encoding: CBOR.map([.unsigned(9): .array([]), .text("Org.example"): .null]).encoded)
    }
    #expect(throws: DiemError.invalidDomain) {
      try ProfileFields(encoding: CBOR.record([9: .array([.text("One.example")])]).encoded)
    }
  }

  @Test func applicationProfilesDecodeTheirOwnContent() async throws {
    let content = NoteProfile.Content(domain: try DomainName("note.example"), note: "hello")
    var identity = try await BasicIdentity<NoteProfile>(content, using: backend)
    let decoded = try NoteProfile(encoding: identity.profile.encoding)
    try await decoded.verify(using: backend)
    #expect(decoded == identity.profile && decoded.content == content && decoded.serves("note.example"))

    var next = identity.profile.content
    next.note = "updated"
    #expect(try await identity.update(next).content.note == "updated")
    #expect(try NoteProfile(record: ProfileRecord(encoding: identity.profile.encoding)).revision == 2)

    let unnamed = try await TestIdentity(.data([1]), using: backend)
    #expect(throws: DiemError.invalidDomain) { try NoteProfile(encoding: unnamed.profile.encoding) }
  }

  @Test func identityDefaultsReturnRevisionsWithoutAdoptingThem() async throws {
    let content = NoteProfile.Content(domain: try DomainName("note.example"), note: "draft")
    let created = try await BasicIdentity<NoteProfile>(content, using: backend)
    let identity = DraftIdentity(profile: created.profile, deviceKey: created.deviceKey,
      identityKey: created.identityKey, backend: backend)
    var next = content
    next.note = "published"
    let revision = try await identity.updating(next)
    #expect(revision.revision == 2 && revision.previousDigest == identity.profile.digest)
    #expect(identity.profile.revision == 1)
    let laptop = try await DevicePrivateKey.generate(using: backend)
    #expect(try await identity.adding(laptop.publicKey).devices.count == 2)
    let proof = try await identity.prove(.bytes([5]), for: .notes)
    try await proof.verify(against: revision, using: backend)
  }

  /// A revision signed by a newer Diem that adds content key 10, carrying the notes field
  /// and another application's field.
  private func sharedIdentity() async throws -> BasicIdentity<NoteProfile> {
    var fields = ProfileFields(domains: [try DomainName("note.example")],
      applications: [.notes: .text("draft"), .test: .bytes([7])])
    fields.extensions = [10: .text("future")]
    let shared = try await TestIdentity(fields, using: backend)
    let decoded = try ProfileRecord(encoding: shared.profile.encoding)
    #expect(decoded.fields == fields)
    return try await BasicIdentity(profile: NoteProfile(record: decoded),
      deviceKey: shared.deviceKey, identityKey: shared.identityKey, using: backend)
  }

  @Test func republishingKeepsOtherApplicationsAndUnknownDiemFields() async throws {
    var identity = try await sharedIdentity()
    func expectKept(_ profile: NoteProfile, note: String = "draft") throws {
      let decoded = try ProfileRecord(encoding: profile.encoding)
      #expect(decoded.fields.applications == [.notes: .text(note), .test: .bytes([7])])
      #expect(decoded.fields.extensions == [10: .text("future")])
    }
    var next = identity.profile.content
    next.note = "published"
    try expectKept(try await identity.update(next), note: "published")
    try expectKept(try await identity.renew(), note: "published")
    let laptop = try await DevicePrivateKey.generate(using: backend)
    try expectKept(try await identity.add(laptop.publicKey), note: "published")
    try expectKept(try await identity.remove(laptop.publicKey.id), note: "published")
    let fresh = try await DevicePrivateKey.generate(using: backend)
    let root = try #require(identity.identityKey)
    try expectKept(try await identity.profile.enrolling(fresh, identityKey: root, using: backend),
      note: "published")
    next.note = "enrolled"
    try expectKept(try await identity.profile.enrolling(fresh, identityKey: root,
      publishing: next, using: backend), note: "enrolled")
  }

  @Test func contentOwnsOnlyItsApplications() async throws {
    let identity = try await sharedIdentity()
    // ProfileRecord's content is the complete fields, so it replaces them all.
    let replaced = try ProfileRecord.fields(for: .data([1]), over: identity.profile.record.fields)
    #expect(replaced == .data([1]))
    await #expect(throws: DiemError.invalidEncoding) {
      try await BasicIdentity<TrespassingProfile>(0, using: backend)
    }
    #expect(throws: DiemError.invalidEncoding) {
      try TrespassingProfile.fields(for: 0, over: identity.profile.record.fields)
    }
  }
}
