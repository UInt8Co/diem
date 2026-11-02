/// An identity root encoded as 24 BIP 39 English recovery words.
///
/// The words encode 256 bits of entropy and a checksum, not a BIP 39 wallet seed.
/// Identity signing seeds use HKDF-SHA256 with an algorithm-qualified identity context.
public struct IdentitySeed: Sendable {
  /// CBOR field keys of the derivation context.
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyPurpose: UInt64 = 2
  public static let cborKeyAlgorithm: UInt64 = 3
  /// The number of words in a phrase.
  public static let wordCount = 24

  /// The 32 bytes of entropy the words encode.
  public let entropy: [UInt8]

  /// The identity seed that encodes 32 bytes of `entropy`.
  public init(entropy: [UInt8]) throws(DiemError) {
    guard entropy.count == 32 else { throw .invalidKey }
    self.entropy = entropy
  }

  /// A new identity seed from the backend's random bytes.
  public static func generate(using backend: some CryptoBackend) throws(DiemError) -> Self {
    try Self(entropy: backend.randomBytes(count: 32))
  }

  /// Decodes a written phrase. Words are separated by whitespace and matched without regard
  /// to ASCII case. An unknown word, a wrong word count or a failed checksum throws
  /// ``DiemError/invalidEncoding``.
  public init(phrase: String) throws(DiemError) {
    let list = PaperWords.all()
    var bytes: [UInt8] = []
    var accumulator: UInt32 = 0
    var bits: UInt32 = 0
    var count = 0
    for word in Self.words(in: phrase) {
      guard count < Self.wordCount, let index = PaperWords.index(of: word, in: list) else {
        throw .invalidEncoding
      }
      count += 1
      accumulator = accumulator << 11 | UInt32(index)
      bits += 11
      while bits >= 8 {
        bits -= 8
        bytes.append(UInt8(truncatingIfNeeded: accumulator >> bits))
      }
      accumulator &= (1 << bits) - 1
    }
    guard count == Self.wordCount, bytes.count == 33 else { throw .invalidEncoding }
    let entropy = Array(bytes[0..<32])
    guard SHA2.sha256(entropy)[0] == bytes[32] else { throw .invalidEncoding }
    self.entropy = entropy
  }

  /// The 24 lowercase words, in order.
  public var words: [String] {
    let list = PaperWords.all()
    var words: [String] = []
    var accumulator: UInt32 = 0
    var bits: UInt32 = 0
    for byte in entropy + [SHA2.sha256(entropy)[0]] {
      accumulator = accumulator << 8 | UInt32(byte)
      bits += 8
      if bits >= 11 {
        bits -= 11
        words.append(String(decoding: list[Int(accumulator >> bits)], as: UTF8.self))
        accumulator &= (1 << bits) - 1
      }
    }
    return words
  }

  /// The words separated by single spaces.
  public var phrase: String { words.joined(separator: " ") }

  /// The identity key seed for `algorithm`. Ed25519 and ML-DSA-65 take the 32 derived bytes;
  /// P-256 throws ``DiemError/unsupportedAlgorithm``.
  func seed(for algorithm: PublicKey.Algorithm) throws(DiemError) -> [UInt8] {
    switch algorithm {
    case .ed25519, .mlDSA65: break
    case .p256: throw .unsupportedAlgorithm
    }
    let context = CBOR.record([
      Self.cborKeyTag: .text("Diem/identity-seed"), Self.cborKeyVersion: .unsigned(1),
      Self.cborKeyPurpose: .unsigned(PublicKey.Purpose.identity.rawValue),
      Self.cborKeyAlgorithm: .unsigned(algorithm.rawValue),
    ]).encoded
    // HKDF-SHA256 (RFC 5869) with an empty salt, for one 32-byte block.
    let pseudorandomKey = Self.hmac(key: [], entropy)
    return Self.hmac(key: pseudorandomKey, context + [1])
  }

  /// Derives the identity key for `algorithm`.
  public func identityKey(
    _ algorithm: PublicKey.Algorithm, using backend: some CryptoBackend
  ) async throws -> IdentityPrivateKey {
    try IdentityPrivateKey(
      await backend.makePrivateKey(algorithm, for: .identity, restoring: seed(for: algorithm)))
  }

  /// Derives and checks the identity key against `identity`.
  public func identityKey(matching identity: IdentityPublicKey, using backend: some CryptoBackend)
    async throws -> IdentityPrivateKey
  {
    let key = try await identityKey(identity.key.algorithm, using: backend)
    guard key.publicKey == identity else { throw DiemError.identityMismatch }
    return key
  }

  /// Lowercase ASCII words of `phrase`, split at whitespace.
  private static func words(in phrase: String) -> [[UInt8]] {
    var words: [[UInt8]] = []
    var word: [UInt8] = []
    for byte in phrase.utf8 {
      if byte == 0x20 || (0x09...0x0d).contains(byte) {
        if !word.isEmpty { words.append(word) }
        word = []
      } else {
        word.append((0x41...0x5a).contains(byte) ? byte | 0x20 : byte)
      }
    }
    if !word.isEmpty { words.append(word) }
    return words
  }

  private static func hmac(key: [UInt8], _ message: [UInt8]) -> [UInt8] {
    let padded = key + [UInt8](repeating: 0, count: 64 - key.count)
    return SHA2.sha256(padded.map { $0 ^ 0x5c } + SHA2.sha256(padded.map { $0 ^ 0x36 } + message))
  }
}

extension PaperWords {
  /// Every word's ASCII bytes, in order.
  static func all() -> [ArraySlice<UInt8>] {
    Array(list.utf8).split(separator: 0x0a)
  }

  /// The position of `word` in the sorted `list`.
  static func index(of word: [UInt8], in list: [ArraySlice<UInt8>]) -> Int? {
    var low = 0
    var high = list.count
    while low < high {
      let middle = (low + high) / 2
      if list[middle].elementsEqual(word) { return middle }
      if list[middle].lexicographicallyPrecedes(word) { low = middle + 1 } else { high = middle }
    }
    return nil
  }
}
