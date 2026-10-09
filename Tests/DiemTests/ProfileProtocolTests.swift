import Diem
import Testing

/// A profile named by exactly one domain, with a note at the first application key.
private struct NoteProfile: DomainNamedProfile {
  struct Content: Hashable, Sendable {
    var domain: DomainName
    var note: String
  }

  static var domainCount: ClosedRange<Int> { 1...1 }

  let record: ProfileRecord
  let content: Content

  init(record: ProfileRecord) throws {
    try Self.validate(domains: record.fields.domains)
    guard let note = record.fields.application[ProfileFields.firstApplicationKey] else {
      throw DiemError.invalidEncoding
    }
    self.record = record
    content = Content(domain: record.fields.domains[0], note: try note.textValue())
  }

  static func fields(for content: Content) throws -> ProfileFields {
    ProfileFields(domains: [content.domain],
      application: [ProfileFields.firstApplicationKey: .text(content.note)])
  }
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
    await #expect(throws: DiemError.invalidEncoding) {
      try await identity.update(ProfileFields(application: [ProfileRecord.cborKeyContentDomains + 1: .null]))
    }
    #expect(try await identity.renew().domains == [one, two])
  }

  @Test func fieldsEncodeAsTheirSignedContentKeys() throws {
    let fields = ProfileFields(domains: [try DomainName("one.example")], application: [16: .unsigned(1)])
    #expect(try CBOR(decoding: fields.encoding)
      == .map([.unsigned(9): .array([.text("one.example")]), .unsigned(16): .unsigned(1)]))
    #expect(try ProfileFields(encoding: fields.encoding) == fields)
    #expect(throws: DiemError.invalidEncoding) {
      try ProfileFields(encoding: CBOR.record([9: .array([]), 10: .null]).encoded)
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
    let proof = try await identity.prove([5])
    try await proof.verify(against: revision, using: backend)
  }
}
