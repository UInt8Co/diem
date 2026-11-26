import Diem
import DiemSwiftCrypto
import Synchronization

/// Swift Crypto with a clock that tests move.
public final class TestBackend: CryptoBackend {
  /// The default starting time, in Unix seconds.
  public static let start: UInt64 = 1_800_000_000

  public let base = SwiftCryptoBackend()
  private let time: Atomic<UInt64>

  public init(now: UInt64 = TestBackend.start) { time = Atomic(now) }

  public var now: UInt64 { time.load(ordering: .relaxed) }
  /// Moves the clock forward.
  public func advance(by seconds: UInt64) { time.add(seconds, ordering: .relaxed) }

  public func randomBytes(count: Int) -> [UInt8] { base.randomBytes(count: count) }
  public func makePrivateKey(
    _ algorithm: PublicKey.Algorithm, for purpose: PublicKey.Purpose, restoring raw: [UInt8]?
  ) async throws -> PrivateKey
  { try await base.makePrivateKey(algorithm, for: purpose, restoring: raw) }
  public func isValidSignature(_ signature: [UInt8], for message: [UInt8], by key: PublicKey)
    async throws -> Bool
  { try await base.isValidSignature(signature, for: message, by: key) }
  public func makeEncryptionKey(_ algorithm: EncryptionPublicKey.Algorithm, restoring raw: [UInt8]?)
    async throws -> EncryptionPrivateKey
  { try await base.makeEncryptionKey(algorithm, restoring: raw) }
  public func seal(_ plaintext: [UInt8], to key: EncryptionPublicKey, context: [UInt8]) async throws
    -> SealedBox
  { try await base.seal(plaintext, to: key, context: context) }
}
