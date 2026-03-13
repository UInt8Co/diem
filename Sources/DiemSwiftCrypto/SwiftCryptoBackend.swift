import Crypto
import Diem
import Foundation

// MARK: - SwiftCryptoBackend

/// A production-ready ``/Diem/DiemCryptoBackend`` implemented using Swift Crypto.
///
/// - ``/Diem/CryptoSet/classic``: HPKE `Curve25519_SHA256_ChachaPoly` + Ed25519.
///   Available on all supported platforms (macOS 14+, iOS 17+, etc.).
/// - ``/Diem/CryptoSet/pqc``: HPKE `XWingMLKEM768X25519_SHA256_AES_GCM_256` + ML-DSA-65.
///   Available on macOS 26+ / iOS 26+. On older Apple OS, PQC operations throw
///   ``/Diem/DiemError/unsupportedCryptoSet(_:)``.
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
      do { key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey) } catch {
        throw DiemError.invalidKey
      }
      do { return [UInt8](try key.signature(for: message)) } catch {
        throw DiemError.encryptionFailed
      }
    case .pqc:
      if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *) {
        let key: MLDSA65.PrivateKey
        do {
          key = try MLDSA65.PrivateKey(seedRepresentation: Data(privateKey), publicKey: nil)
        } catch { throw DiemError.invalidKey }
        do { return [UInt8](try key.signature(for: message)) } catch {
          throw DiemError.encryptionFailed
        }
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
      do { key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey) } catch {
        throw DiemError.invalidKey
      }
      return key.isValidSignature(signature, for: message)
    case .pqc:
      if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *) {
        let key: MLDSA65.PublicKey
        do { key = try MLDSA65.PublicKey(rawRepresentation: publicKey) } catch {
          throw DiemError.invalidKey
        }
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
    do {
      pubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKey)
    } catch { throw DiemError.invalidKey }
    var sender: HPKE.Sender
    do {
      sender = try HPKE.Sender(
        recipientKey: pubKey, ciphersuite: .Curve25519_SHA256_ChachaPoly,
        info: SwiftCryptoBackend.hpkeInfo)
    } catch { throw DiemError.encryptionFailed }
    let encKey = [UInt8](sender.encapsulatedKey)
    let ct: [UInt8]
    do { ct = [UInt8](try sender.seal(plaintext)) } catch { throw DiemError.encryptionFailed }
    return (encKey, ct)
  }

  @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
  private func _hpkeEncryptPQC(
    plaintext: [UInt8], recipientPublicKey: [UInt8]
  ) throws -> (encapsulatedKey: [UInt8], ciphertext: [UInt8]) {
    let pubKey: XWingMLKEM768X25519.PublicKey
    do { pubKey = try XWingMLKEM768X25519.PublicKey(rawRepresentation: recipientPublicKey) } catch {
      throw DiemError.invalidKey
    }
    var sender: HPKE.Sender
    do {
      sender = try HPKE.Sender(
        recipientKey: pubKey, ciphersuite: .XWingMLKEM768X25519_SHA256_AES_GCM_256,
        info: SwiftCryptoBackend.hpkeInfo)
    } catch { throw DiemError.encryptionFailed }
    let encKey = [UInt8](sender.encapsulatedKey)
    let ct: [UInt8]
    do { ct = [UInt8](try sender.seal(plaintext)) } catch { throw DiemError.encryptionFailed }
    return (encKey, ct)
  }

  private func _hpkeDecryptClassic(
    ciphertext: [UInt8], encapsulatedKey: [UInt8], recipientPrivateKey: [UInt8]
  ) throws -> [UInt8] {
    let privKey: Curve25519.KeyAgreement.PrivateKey
    do {
      privKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: recipientPrivateKey)
    } catch { throw DiemError.invalidKey }
    var recipient: HPKE.Recipient
    do {
      recipient = try HPKE.Recipient(
        privateKey: privKey, ciphersuite: .Curve25519_SHA256_ChachaPoly,
        info: SwiftCryptoBackend.hpkeInfo, encapsulatedKey: Data(encapsulatedKey))
    } catch { throw DiemError.decryptionFailed }
    do { return [UInt8](try recipient.open(ciphertext)) } catch { throw DiemError.decryptionFailed }
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
    do { return [UInt8](try recipient.open(ciphertext)) } catch { throw DiemError.decryptionFailed }
  }
}

// MARK: - Symmetric encryption

extension SwiftCryptoBackend {
  public func symmetricEncrypt(
    plaintext: [UInt8], key: [UInt8], crypto: EncryptedShare.Crypto
  ) throws -> [UInt8] {
    switch crypto {
    case .aes256gcm:
      return try _aes256gcmEncrypt(plaintext: plaintext, key: key)
    }
  }

  public func symmetricDecrypt(
    ciphertext: [UInt8], key: [UInt8], crypto: EncryptedShare.Crypto
  ) throws -> [UInt8] {
    switch crypto {
    case .aes256gcm:
      return try _aes256gcmDecrypt(ciphertext: ciphertext, key: key)
    }
  }

  private func _aes256gcmEncrypt(plaintext: [UInt8], key: [UInt8]) throws -> [UInt8] {
    let symKey: SymmetricKey
    do {
      symKey = SymmetricKey(data: key)
    } catch {
      throw DiemError.invalidKey
    }

    // Generate a random 12-byte nonce (96 bits, standard for GCM)
    let nonce = AES.GCM.Nonce()

    let sealedBox: AES.GCM.SealedBox
    do {
      sealedBox = try AES.GCM.seal(plaintext, using: symKey, nonce: nonce)
    } catch {
      throw DiemError.encryptionFailed
    }

    // Combine nonce + ciphertext + tag
    // Format: [nonce (12 bytes)][ciphertext][tag (16 bytes)]
    var result = [UInt8]()
    result.append(contentsOf: sealedBox.nonce)
    result.append(contentsOf: sealedBox.ciphertext)
    result.append(contentsOf: sealedBox.tag)
    return result
  }

  private func _aes256gcmDecrypt(ciphertext: [UInt8], key: [UInt8]) throws -> [UInt8] {
    let symKey: SymmetricKey
    do {
      symKey = SymmetricKey(data: key)
    } catch {
      throw DiemError.invalidKey
    }

    // Extract nonce (12 bytes), ciphertext, and tag (16 bytes)
    guard ciphertext.count >= 12 + 16 else {
      throw DiemError.decryptionFailed
    }

    let nonceBytes = ciphertext[0..<12]
    let tagStart = ciphertext.count - 16
    let ciphertextBytes = ciphertext[12..<tagStart]
    let tagBytes = ciphertext[tagStart...]

    let nonce: AES.GCM.Nonce
    do {
      nonce = try AES.GCM.Nonce(data: Data(nonceBytes))
    } catch {
      throw DiemError.decryptionFailed
    }

    let sealedBox: AES.GCM.SealedBox
    do {
      sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: Data(ciphertextBytes), tag: Data(tagBytes))
    } catch {
      throw DiemError.decryptionFailed
    }

    do {
      let plaintext = try AES.GCM.open(sealedBox, using: symKey)
      return [UInt8](plaintext)
    } catch {
      throw DiemError.decryptionFailed
    }
  }
}

// MARK: - Key ID

extension SwiftCryptoBackend {
  /// Returns the SHA-256 digest of `key` as a 32-byte stable identifier.
  public func keyID(of key: [UInt8]) -> [UInt8] {
    var hasher = SHA256()
    key.withUnsafeBufferPointer { ptr in
      hasher.update(bufferPointer: UnsafeRawBufferPointer(ptr))
    }
    return [UInt8](hasher.finalize())
  }

  /// Returns `count` cryptographically random bytes using `SystemRandomNumberGenerator`.
  public func generateRandomBytes(count: Int) -> [UInt8] {
    var rng = SystemRandomNumberGenerator()
    return (0..<count).map { _ in rng.next() }
  }
}
