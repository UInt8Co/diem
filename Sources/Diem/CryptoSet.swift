/// Identifies which set of cryptographic algorithms to use.
///
/// Each crypto set defines a pairing of a signing algorithm and an HPKE encryption scheme:
///
/// | Set | Signing | Encryption |
/// |-----|---------|------------|
/// | ``classic`` | Ed25519 | HPKE `Curve25519_SHA256_ChachaPoly` |
/// | ``pqc`` | ML-DSA-65 | HPKE `XWingMLKEM768X25519_SHA256_AES_GCM_256` |
///
/// New sets may be added in future versions. Backends declare which sets they support via
/// ``DiemCryptoBackend/supportedCryptoSets``.
public enum CryptoSet: UInt64, Sendable, Hashable, CaseIterable {
  /// Classical elliptic-curve cryptography using Curve25519 / Ed25519.
  case classic = 0
  /// Post-quantum cryptography using X-Wing (ML-KEM-768 + X25519) and ML-DSA-65.
  case pqc = 1
}
