import Diem

public struct ProofOfWorkPuzzle: Sendable, Equatable {
  public let domain: DomainName
  public let label: String
  public let identityID: Digest
  public let requiredBits: Int
  /// The SHA-256 input before appending the nonce.
  public let input: [UInt8]

  public init(domain: DomainName, label: String, identityID: Digest, requiredBits: Int)
    throws(ProfileHostingError)
  {
    guard validWireLabel(label, domain: domain) else { throw .invalidLabel(label) }
    guard (0...64).contains(requiredBits) else { throw .unsolvable(label) }
    self.domain = domain
    self.label = label
    self.identityID = identityID
    self.requiredBits = requiredBits
    input = Array(("diem-profile-hosting-pow-v1\0" + domain.name + "\0" + label + "\0").utf8)
      + identityID.bytes
  }

  /// Mean attempts for an independent uniformly distributed hash: 2^requiredBits.
  public var expectedAttempts: Double {
    (0..<requiredBits).reduce(1.0) { value, _ in value * 2 }
  }

  /// `baseBits + bitsPerShorterCharacter × max(0, referenceLength − label.utf8.count)` in
  /// signed 64-bit arithmetic on every platform, as hosts compute it. Nil means overflow or
  /// a requirement outside 0...64. The apex (`@`) requires an explicit host requirement.
  public static func requiredBits(for label: String, baseBits: Int64,
    bitsPerShorterCharacter: Int64, referenceLength: Int64
  ) -> Int? {
    guard label != "@" else { return nil }
    let (shortfall, underflow) = referenceLength.subtractingReportingOverflow(Int64(label.utf8.count))
    let (extra, overflow) = bitsPerShorterCharacter.multipliedReportingOverflow(by: max(0, shortfall))
    let (bits, additionOverflow) = baseBits.addingReportingOverflow(extra)
    guard !underflow, !overflow, !additionOverflow, (0...64).contains(bits) else { return nil }
    return Int(bits)
  }

  public func isSolved(by nonce: [UInt8]) -> Bool {
    guard (1...64).contains(nonce.count) else { return false }
    if requiredBits == 0 { return true }
    var leading = 0
    for byte in SHA2.sha256(input + nonce) {
      leading += byte.leadingZeroBitCount
      if byte != 0 { break }
    }
    return leading >= requiredBits
  }
}

public protocol ProofOfWorkSolver: Sendable {
  func solve(_ puzzle: ProofOfWorkPuzzle) async throws -> [UInt8]
}

/// A portable fallback using Diem's SHA-256 and eight-byte big-endian counters from zero.
public struct PortableProofOfWorkSolver: ProofOfWorkSolver {
  public init() {}

  public func solve(_ puzzle: ProofOfWorkPuzzle) async throws -> [UInt8] {
    var counter: UInt64 = 0
    while true {
      if counter % 1024 == 0 {
        try checkHostingCancellation()
        await Task.yield()
        try checkHostingCancellation()
      }
      let nonce = (0..<8).reversed().map { UInt8(truncatingIfNeeded: counter >> ($0 * 8)) }
      if puzzle.isSolved(by: nonce) { return nonce }
      guard counter != UInt64.max else { throw ProfileHostingError.unsolvable(puzzle.label) }
      counter += 1
    }
  }
}

func validLabel(_ label: String, domain: DomainName) -> Bool {
  !label.utf8.contains(46) && DomainName.isValid(label + "." + domain.name)
}

/// A wire label is a lowercase DNS child label or the reserved apex label `@`.
func validWireLabel(_ label: String, domain: DomainName? = nil) -> Bool {
  label == "@" || (!label.utf8.contains(46)
    && DomainName.isValid(label + "." + (domain?.name ?? "example")))
}

/// The server's comma-separated, sorted label=nonce grammar, with unpadded base64url.
/// Labels may be lowercase DNS child labels or `@` for the apex.
public func hostingProofHeader(_ proofs: [String: [UInt8]]) throws(ProfileHostingError) -> String {
  var entries: [String] = []
  for label in proofs.keys.sorted() {
    guard validWireLabel(label) else {
      throw .invalidLabel(label)
    }
    let nonce = proofs[label]!
    guard (1...64).contains(nonce.count) else { throw .invalidProof(label) }
    entries.append(label + "=" + Base64URL.encode(nonce))
  }
  return entries.joined(separator: ", ")
}

/// The inverse of ``hostingProofHeader(_:)``, as hosts parse it: spaces and tabs may surround
/// labels, `=` and nonces. Nil when an entry is malformed, a label repeats, a nonce is not
/// 1...64 bytes of canonical unpadded base64url, or there are more than `limit` entries.
public func hostingProofs(fromHeader header: String, limit: Int) -> [String: [UInt8]]? {
  var proofs: [String: [UInt8]] = [:]
  var entries = 0
  for entry in Array(header.utf8).split(separator: 44, omittingEmptySubsequences: false) {
    entries += 1
    guard entries <= limit else { return nil }
    let pair = entry.split(separator: 61, omittingEmptySubsequences: false)
    guard pair.count == 2 else { return nil }
    let label = String(decoding: trimmingBlanks(pair[0]), as: UTF8.self)
    guard validWireLabel(label), proofs[label] == nil,
      let nonce = Base64URL.decode(utf8: trimmingBlanks(pair[1])), (1...64).contains(nonce.count)
    else { return nil }
    proofs[label] = nonce
  }
  return proofs
}

private func trimmingBlanks(_ bytes: ArraySlice<UInt8>) -> ArraySlice<UInt8> {
  var bytes = bytes
  while let first = bytes.first, first == 32 || first == 9 { bytes.removeFirst() }
  while let last = bytes.last, last == 32 || last == 9 { bytes.removeLast() }
  return bytes
}
