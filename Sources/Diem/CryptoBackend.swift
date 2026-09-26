import DiemPortable

/// Public cryptography plus symmetric encryption for private shares. Device key
/// custody is expressed by DeviceSigningKey/DeviceWrappingKey, never raw private bytes.
public protocol DiemCryptoBackend: DeviceCrypto {
  func symmetricEncrypt(plaintext: [UInt8], key: [UInt8]) throws -> [UInt8]
  func symmetricDecrypt(ciphertext: [UInt8], key: [UInt8]) throws -> [UInt8]
}
