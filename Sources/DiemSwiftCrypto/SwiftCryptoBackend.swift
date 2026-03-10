import Foundation
import Crypto
import Diem

// MARK: - SwiftCryptoBackend

/// A production-ready ``DiemCryptoBackend`` implemented using Swift Crypto.
///
/// - ``CryptoSet/classic``: HPKE `Curve25519_SHA256_ChachaPoly` + Ed25519.
///   Available on all supported platforms (macOS 14+, iOS 17+, etc.).
/// - ``CryptoSet/pqc``: HPKE `XWingMLKEM768X25519_SHA256_AES_GCM_256` + ML-DSA-65.
///   Available on macOS 26+ / iOS 26+. On older Apple OS, PQC operations throw
///   ``DiemError/unsupportedCryptoSet(_:)``.
///
/// All private keys are stored as 32-byte seed representations:
/// - Classic signing: `Curve25519.Signing.PrivateKey.rawRepresentation`
/// - Classic encryption: `Curve25519.KeyAgreement.PrivateKey.rawRepresentation`
/// - PQC signing: `MLDSA65.PrivateKey.seedRepresentation`
/// - PQC encryption: `XWingMLKEM768X25519.PrivateKey.seedRepresentation`
public struct SwiftCryptoBackend: DiemCryptoBackend, Sendable {
  public init() {}

  public var supportedCryptoSets: Set<CryptoSet> {
    var sets: Set<CryptoSet> = [.classic]
    if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *) {
      sets.insert(.pqc)
    }
    return sets
  }

  // Context string bound into every HPKE operation.
  fileprivate static let hpkeInfo = Data("Diem/v1/EncryptedMessage".utf8)
}

// MARK: - Key generation

extension SwiftCryptoBackend {
  public func generateSigningKeyPair(for cryptoSet: CryptoSet) throws -> (
    publicKey: [UInt8], privateKey: [UInt8]
  ) {
    switch cryptoSet {
    case .classic:
      let key = Curve25519.Signing.PrivateKey()
      return ([UInt8](key.publicKey.rawRepresentation), [UInt8](key.rawRepresentation))
    case .pqc:
      if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *) {
        let key = try MLDSA65.PrivateKey()
        return ([UInt8](key.publicKey.rawRepresentation), [UInt8](key.seedRepresentation))
      } else {
        throw DiemError.unsupportedCryptoSet(cryptoSet)
      }
    }
  }

  public func generateEncryptionKeyPair(for cryptoSet: CryptoSet) throws -> (
    publicKey: [UInt8], privateKey: [UInt8]
  ) {
    switch cryptoSet {
    case .classic:
      let key = Curve25519.KeyAgreement.PrivateKey()
      return ([UInt8](key.publicKey.rawRepresentation), [UInt8](key.rawRepresentation))
    case .pqc:
      if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *) {
        let key = try XWingMLKEM768X25519.PrivateKey()
        return ([UInt8](key.publicKey.rawRepresentation), [UInt8](key.seedRepresentation))
      } else {
        throw DiemError.unsupportedCryptoSet(cryptoSet)
      }
    }
  }
}

// MARK: - Signing

extension SwiftCryptoBackend {
  public func sign(
    message: [UInt8], privateKey: [UInt8], cryptoSet: CryptoSet
  ) throws -> [UInt8] {
    switch cryptoSet {
    case .classic:
      let key: Curve25519.Signing.PrivateKey
      do { key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey) }
      catch { throw DiemError.invalidKey }
      do { return [UInt8](try key.signature(for: message)) }
      catch { throw DiemError.encryptionFailed }
    case .pqc:
      if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *) {
        let key: MLDSA65.PrivateKey
        do { key = try MLDSA65.PrivateKey(seedRepresentation: Data(privateKey), publicKey: nil) }
        catch { throw DiemError.invalidKey }
        do { return [UInt8](try key.signature(for: message)) }
        catch { throw DiemError.encryptionFailed }
      } else {
        throw DiemError.unsupportedCryptoSet(cryptoSet)
      }
    }
  }

  public func verify(
    signature: [UInt8], message: [UInt8], publicKey: [UInt8], cryptoSet: CryptoSet
  ) throws -> Bool {
    switch cryptoSet {
    case .classic:
      let key: Curve25519.Signing.PublicKey
      do { key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey) }
      catch { throw DiemError.invalidKey }
      return key.isValidSignature(signature, for: message)
    case .pqc:
      if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *) {
        let key: MLDSA65.PublicKey
        do { key = try MLDSA65.PublicKey(rawRepresentation: publicKey) }
        catch { throw DiemError.invalidKey }
        return key.isValidSignature(signature, for: message)
      } else {
        throw DiemError.unsupportedCryptoSet(cryptoSet)
      }
    }
  }
}

// MARK: - HPKE encryption / decryption

extension SwiftCryptoBackend {
  public func hpkeEncrypt(
    plaintext: [UInt8], recipientPublicKey: [UInt8], cryptoSet: CryptoSet
  ) throws -> (encapsulatedKey: [UInt8], ciphertext: [UInt8]) {
    switch cryptoSet {
    case .classic:
      return try _hpkeEncryptClassic(plaintext: plaintext, recipientPublicKey: recipientPublicKey)
    case .pqc:
      if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *) {
        return try _hpkeEncryptPQC(plaintext: plaintext, recipientPublicKey: recipientPublicKey)
      } else {
        throw DiemError.unsupportedCryptoSet(cryptoSet)
      }
    }
  }

  public func hpkeDecrypt(
    ciphertext: [UInt8], encapsulatedKey: [UInt8], recipientPrivateKey: [UInt8],
    cryptoSet: CryptoSet
  ) throws -> [UInt8] {
    switch cryptoSet {
    case .classic:
      return try _hpkeDecryptClassic(
        ciphertext: ciphertext, encapsulatedKey: encapsulatedKey,
        recipientPrivateKey: recipientPrivateKey)
    case .pqc:
      if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *) {
        return try _hpkeDecryptPQC(
          ciphertext: ciphertext, encapsulatedKey: encapsulatedKey,
          recipientPrivateKey: recipientPrivateKey)
      } else {
        throw DiemError.unsupportedCryptoSet(cryptoSet)
      }
    }
  }
}

// MARK: - HPKE helpers (availability-gated for PQC)

extension SwiftCryptoBackend {
  private func _hpkeEncryptClassic(
    plaintext: [UInt8], recipientPublicKey: [UInt8]
  ) throws -> (encapsulatedKey: [UInt8], ciphertext: [UInt8]) {
    let pubKey: Curve25519.KeyAgreement.PublicKey
    do { pubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKey) }
    catch { throw DiemError.invalidKey }
    var sender: HPKE.Sender
    do {
      sender = try HPKE.Sender(
        recipientKey: pubKey, ciphersuite: .Curve25519_SHA256_ChachaPoly,
        info: SwiftCryptoBackend.hpkeInfo)
    } catch { throw DiemError.encryptionFailed }
    let encKey = [UInt8](sender.encapsulatedKey)
    let ct: [UInt8]
    do { ct = [UInt8](try sender.seal(plaintext)) }
    catch { throw DiemError.encryptionFailed }
    return (encKey, ct)
  }

  @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
  private func _hpkeEncryptPQC(
    plaintext: [UInt8], recipientPublicKey: [UInt8]
  ) throws -> (encapsulatedKey: [UInt8], ciphertext: [UInt8]) {
    let pubKey: XWingMLKEM768X25519.PublicKey
    do { pubKey = try XWingMLKEM768X25519.PublicKey(rawRepresentation: recipientPublicKey) }
    catch { throw DiemError.invalidKey }
    var sender: HPKE.Sender
    do {
      sender = try HPKE.Sender(
        recipientKey: pubKey, ciphersuite: .XWingMLKEM768X25519_SHA256_AES_GCM_256,
        info: SwiftCryptoBackend.hpkeInfo)
    } catch { throw DiemError.encryptionFailed }
    let encKey = [UInt8](sender.encapsulatedKey)
    let ct: [UInt8]
    do { ct = [UInt8](try sender.seal(plaintext)) }
    catch { throw DiemError.encryptionFailed }
    return (encKey, ct)
  }

  private func _hpkeDecryptClassic(
    ciphertext: [UInt8], encapsulatedKey: [UInt8], recipientPrivateKey: [UInt8]
  ) throws -> [UInt8] {
    let privKey: Curve25519.KeyAgreement.PrivateKey
    do { privKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: recipientPrivateKey) }
    catch { throw DiemError.invalidKey }
    var recipient: HPKE.Recipient
    do {
      recipient = try HPKE.Recipient(
        privateKey: privKey, ciphersuite: .Curve25519_SHA256_ChachaPoly,
        info: SwiftCryptoBackend.hpkeInfo, encapsulatedKey: Data(encapsulatedKey))
    } catch { throw DiemError.decryptionFailed }
    do { return [UInt8](try recipient.open(ciphertext)) }
    catch { throw DiemError.decryptionFailed }
  }

  @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
  private func _hpkeDecryptPQC(
    ciphertext: [UInt8], encapsulatedKey: [UInt8], recipientPrivateKey: [UInt8]
  ) throws -> [UInt8] {
    let privKey: XWingMLKEM768X25519.PrivateKey
    do {
      privKey = try XWingMLKEM768X25519.PrivateKey(
        seedRepresentation: Data(recipientPrivateKey), publicKey: nil)
    } catch { throw DiemError.invalidKey }
    var recipient: HPKE.Recipient
    do {
      recipient = try HPKE.Recipient(
        privateKey: privKey, ciphersuite: .XWingMLKEM768X25519_SHA256_AES_GCM_256,
        info: SwiftCryptoBackend.hpkeInfo, encapsulatedKey: Data(encapsulatedKey))
    } catch { throw DiemError.decryptionFailed }
    do { return [UInt8](try recipient.open(ciphertext)) }
    catch { throw DiemError.decryptionFailed }
  }
}

// MARK: - Key ID

extension SwiftCryptoBackend {
  /// Returns the SHA-256 digest of `publicKey` as a 32-byte stable identifier.
  public func keyID(publicKey: [UInt8]) -> [UInt8] {
    var hasher = SHA256()
    publicKey.withUnsafeBufferPointer { ptr in
      hasher.update(bufferPointer: UnsafeRawBufferPointer(ptr))
    }
    return [UInt8](hasher.finalize())
  }
}
