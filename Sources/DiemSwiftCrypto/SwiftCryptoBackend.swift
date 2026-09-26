import Crypto
import Diem
import Foundation

public typealias SwiftCryptoBackend = SoftwareDeviceCrypto

extension SoftwareDeviceCrypto: DiemCryptoBackend {
  public func symmetricEncrypt(plaintext: [UInt8], key: [UInt8]) throws -> [UInt8] {
    guard key.count == 32 else { throw DiemError.invalidKey }
    return Array(try AES.GCM.seal(plaintext, using: SymmetricKey(data: key)).combined!)
  }
  public func symmetricDecrypt(ciphertext: [UInt8], key: [UInt8]) throws -> [UInt8] {
    guard key.count == 32 else { throw DiemError.invalidKey }
    return Array(
      try AES.GCM.open(AES.GCM.SealedBox(combined: ciphertext), using: SymmetricKey(data: key)))
  }
}
