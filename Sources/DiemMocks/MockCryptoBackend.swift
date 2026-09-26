import Diem

/// Test-only backend; never validates signatures or encrypts. Production targets
/// must depend on a real cryptographic provider instead.
public struct MockCryptoBackend: DiemCryptoBackend {
  public init() {}
  public func sha256(_ message: [UInt8]) -> [UInt8] { [UInt8](repeating: 0, count: 32) }
  public func randomBytes(count: Int) -> [UInt8] { [UInt8](repeating: 0, count: count) }
  public func verify(_ signature: [UInt8], message: [UInt8], key: DevicePublicKey) throws(DiemError)
    -> Bool
  {
    false
  }
  public func seal(_ plaintext: [UInt8], to key: DevicePublicKey, context: [UInt8])
    throws(DiemError)
    -> WrappedSecret
  {
    throw DiemError.encryptionFailed
  }
  public func symmetricEncrypt(plaintext: [UInt8], key: [UInt8]) throws(DiemError) -> [UInt8] {
    throw DiemError.encryptionFailed
  }
  public func symmetricDecrypt(ciphertext: [UInt8], key: [UInt8]) throws(DiemError) -> [UInt8] {
    throw DiemError.decryptionFailed
  }
}
