/// A software device key written down as 24 words, so a sheet of paper can be one of an
/// identity's devices.
///
/// The words are the BIP 39 English encoding of 256 bits of entropy, whose checksum catches
/// a mistyped word. The key is not BIP 39's wallet seed: its seed for an algorithm is
/// HKDF-SHA256 of the entropy with an empty salt and the canonical derivation context as
/// info. An identity certifies the derived public key like any other device, so the paper
/// proves wherever its profile lists it and is removed the same way. Like every device
/// key, it cannot certify devices or recover the identity key.
public struct PaperDeviceKey: Sendable {
  /// CBOR field keys of the derivation context.
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyPurpose: UInt64 = 2
  public static let cborKeyAlgorithm: UInt64 = 3
  /// The number of words in a phrase.
  public static let wordCount = 24

  /// The 32 bytes of entropy the words encode.
  public let entropy: [UInt8]

  /// The paper key that encodes 32 bytes of `entropy`.
  public init(entropy: [UInt8]) throws(DiemError) {
    guard entropy.count == 32 else { throw .invalidKey }
    self.entropy = entropy
  }

  /// A new paper key from the backend's random bytes.
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

  /// The device key seed for `algorithm`. Ed25519 and ML-DSA-65 take the 32 derived bytes;
  /// P-256 keys belong in hardware and throw ``DiemError/unsupportedAlgorithm``.
  public func seed(for algorithm: PublicKey.Algorithm) throws(DiemError) -> [UInt8] {
    switch algorithm {
    case .ed25519, .mlDSA65: break
    case .p256: throw .unsupportedAlgorithm
    }
    let context = CBOR.record([
      Self.cborKeyTag: .text("Diem/paper-device-key"), Self.cborKeyVersion: .unsigned(1),
      Self.cborKeyPurpose: .unsigned(PublicKey.Purpose.device.rawValue),
      Self.cborKeyAlgorithm: .unsigned(algorithm.rawValue),
    ]).encoded
    // HKDF-SHA256 (RFC 5869) with an empty salt, for one 32-byte block.
    let pseudorandomKey = Self.hmac(key: [], entropy)
    return Self.hmac(key: pseudorandomKey, context + [1])
  }

  /// The paper's device key for `algorithm`, ML-DSA-65 by default.
  public func deviceKey(
    _ algorithm: PublicKey.Algorithm = .mlDSA65, using backend: some CryptoBackend
  ) async throws -> DevicePrivateKey {
    try DevicePrivateKey(
      await backend.makePrivateKey(algorithm, for: .device, restoring: seed(for: algorithm)))
  }

  /// The paper's device key that `profile` certifies, whichever algorithm it uses. A
  /// profile that lists none of the paper's keys throws ``DiemError/deviceNotListed``.
  public func deviceKey(listedIn profile: some Profile, using backend: some CryptoBackend)
    async throws -> DevicePrivateKey
  {
    var tried: [PublicKey.Algorithm] = []
    for certificate in profile.devices {
      let algorithm = certificate.device.key.algorithm
      guard algorithm != .p256, !tried.contains(algorithm) else { continue }
      tried.append(algorithm)
      let key = try await deviceKey(algorithm, using: backend)
      if profile.devices.contains(where: { $0.device == key.publicKey }) { return key }
    }
    throw DiemError.deviceNotListed
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
