#if canImport(CryptoKit) && canImport(Security)
  import CryptoKit
  import Diem
  import Foundation
  import Security

  /// The stored blobs are Secure Enclave references bound to their original device,
  /// not exported private keys. Restore them only on that same device.
  public struct SecureEnclaveSigningKey: DeviceSigningKey {
    private let key: SecureEnclave.P256.Signing.PrivateKey
    public let publicKey: DevicePublicKey
    public let protection = KeyProtection.secureEnclave
    public var persistentReference: Data { key.dataRepresentation }

    public init(accessControl: SecAccessControl) throws {
      guard SecureEnclave.isAvailable else { throw DiemError.keyNotFound }
      let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
      self.key = key
      self.publicKey = try DevicePublicKey(
        algorithm: .p256Signing,
        rawRepresentation: Array(key.publicKey.x963Representation))
    }
    public init(persistentReference: Data) throws {
      let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: persistentReference)
      self.key = key
      self.publicKey = try DevicePublicKey(
        algorithm: .p256Signing,
        rawRepresentation: Array(key.publicKey.x963Representation))
    }
    public func signature(for message: [UInt8]) throws(DiemError) -> [UInt8] {
      try normalizeCryptoFailure(.encryptionFailed) {
        try Array(key.signature(for: message).rawRepresentation)
      }
    }
  }

  public struct SecureEnclaveWrappingKey: DeviceWrappingKey {
    private let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    public let publicKey: DevicePublicKey
    public let protection = KeyProtection.secureEnclave
    public var persistentReference: Data { key.dataRepresentation }

    public init(accessControl: SecAccessControl) throws {
      guard SecureEnclave.isAvailable else { throw DiemError.keyNotFound }
      let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl)
      self.key = key
      self.publicKey = try DevicePublicKey(
        algorithm: .p256Agreement,
        rawRepresentation: Array(key.publicKey.x963Representation))
    }
    public init(persistentReference: Data) throws {
      let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
        dataRepresentation: persistentReference)
      self.key = key
      self.publicKey = try DevicePublicKey(
        algorithm: .p256Agreement,
        rawRepresentation: Array(key.publicKey.x963Representation))
    }
    public func open(_ box: WrappedSecret, context: [UInt8]) throws(DiemError) -> [UInt8] {
      try normalizeCryptoFailure(.decryptionFailed) {
        var recipient = try HPKE.Recipient(
          privateKey: key, ciphersuite: .P256_SHA256_AES_GCM_256,
          info: Data(context), encapsulatedKey: Data(box.encapsulatedKey))
        return try Array(recipient.open(box.ciphertext, authenticating: context))
      }
    }
  }
#endif
