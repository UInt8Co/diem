import CBOR

// MARK: - SignedMessage

/// A message that carries a CBOR payload and a digital signature over it.
///
/// The ``senderKeyID`` and ``cryptoSet`` are stored unencrypted so the recipient can
/// look up the sender's signing public key.  ``payloadBytes`` stores the exact bytes
/// that were signed, ensuring stable verification across re-encodings.
///
/// Serialised as a CBOR map with integer keys (see ``toCBOR()``).
public struct SignedMessage: Sendable {
  /// The key ID of the sender's signing public key.
  public let senderKeyID: [UInt8]
  /// Which crypto set was used for signing.
  public let cryptoSet: CryptoSet
  /// The decoded CBOR payload.
  public let payload: CBOR
  /// The signature over ``payloadBytes``.
  public let signature: [UInt8]

  /// The exact CBOR bytes that were signed, preserved for stable verification.
  public let payloadBytes: [UInt8]

  public init(
    senderKeyID: [UInt8],
    cryptoSet: CryptoSet,
    payload: CBOR,
    payloadBytes: [UInt8],
    signature: [UInt8]
  ) {
    self.senderKeyID = senderKeyID
    self.cryptoSet = cryptoSet
    self.payload = payload
    self.payloadBytes = payloadBytes
    self.signature = signature
  }
}

// MARK: - Verification

extension SignedMessage {
  /// Verifies the signature against a specific `signingKey`.
  ///
  /// - Parameters:
  ///   - signingKey: A ``PublicKeyEntry`` whose `keyType` is ``KeyType/signing``.
  ///   - backend: The crypto backend to use.
  /// - Returns: `true` when the signature is valid.
  /// - Throws: ``DiemError/invalidKeyType`` if the key is not a signing key or its
  ///           `cryptoSet` does not match this message's `cryptoSet`.
  public func verify<Backend: DiemCryptoBackend>(
    against signingKey: PublicKeyEntry, using backend: Backend
  ) throws -> Bool {
    guard signingKey.keyType == .signing else { throw DiemError.invalidKeyType }
    guard signingKey.cryptoSet == cryptoSet else { throw DiemError.invalidKeyType }
    guard backend.supportedCryptoSets.contains(cryptoSet) else {
      throw DiemError.unsupportedCryptoSet(cryptoSet)
    }
    return try backend.verify(
      signature: signature, message: payloadBytes, publicKey: signingKey.rawBytes,
      cryptoSet: cryptoSet)
  }

  /// Verifies the signature using the matching signing key from `senderProfile`.
  ///
  /// Searches `senderProfile` for a signing key whose `id` matches `senderKeyID`
  /// and whose `cryptoSet` matches this message's `cryptoSet`.
  ///
  /// - Throws: ``DiemError/keyNotFound`` if no matching key is found in the profile.
  public func verify<Backend: DiemCryptoBackend>(
    using senderProfile: Profile, with backend: Backend
  ) throws -> Bool {
    guard
      let key = senderProfile.keys.first(where: {
        $0.id == senderKeyID && $0.keyType == .signing && $0.cryptoSet == cryptoSet
      })
    else {
      throw DiemError.keyNotFound
    }
    return try verify(against: key, using: backend)
  }
}

// MARK: - CBOR serialisation

extension SignedMessage {
  private enum Field: UInt64 {
    case senderKeyID = 0
    case cryptoSet = 1
    case payloadBytes = 2
    case signature = 3
  }

  /// Encodes this message as a CBOR map with integer keys.
  public func toCBOR() -> CBOR {
    .map([
      CBORMapPair(
        key: .unsignedInt(Field.senderKeyID.rawValue),
        value: .byteString(ArraySlice(senderKeyID))),
      CBORMapPair(
        key: .unsignedInt(Field.cryptoSet.rawValue),
        value: .unsignedInt(cryptoSet.rawValue)),
      CBORMapPair(
        key: .unsignedInt(Field.payloadBytes.rawValue),
        value: .byteString(ArraySlice(payloadBytes))),
      CBORMapPair(
        key: .unsignedInt(Field.signature.rawValue),
        value: .byteString(ArraySlice(signature))),
    ])
  }

  /// Decodes a ``SignedMessage`` from a CBOR map.
  public static func fromCBOR(_ cbor: CBOR) throws -> SignedMessage {
    guard let pairs = try cbor.mapValue() else { throw DiemError.invalidCBOR }
    var senderKeyID: [UInt8]?
    var cryptoSetRaw: UInt64?
    var payloadBytes: [UInt8]?
    var signature: [UInt8]?
    for pair in pairs {
      guard case .unsignedInt(let k) = pair.key else { continue }
      switch k {
      case Field.senderKeyID.rawValue: senderKeyID = pair.value.byteStringValue()
      case Field.cryptoSet.rawValue:
        if case .unsignedInt(let v) = pair.value { cryptoSetRaw = v }
      case Field.payloadBytes.rawValue: payloadBytes = pair.value.byteStringValue()
      case Field.signature.rawValue: signature = pair.value.byteStringValue()
      default: break
      }
    }
    guard let senderKeyID, let cryptoSetRaw, let payloadBytes, let signature else {
      throw DiemError.missingField(
        "SignedMessage: senderKeyID, cryptoSet, payloadBytes, or signature missing")
    }
    guard let cryptoSet = CryptoSet(rawValue: cryptoSetRaw) else { throw DiemError.invalidCBOR }
    let payload: CBOR
    do { payload = try CBOR.decode(payloadBytes) } catch { throw DiemError.invalidCBOR }
    return SignedMessage(
      senderKeyID: senderKeyID, cryptoSet: cryptoSet, payload: payload,
      payloadBytes: payloadBytes, signature: signature)
  }

  /// Serialises this message to CBOR bytes.
  public func encode() -> [UInt8] { toCBOR().encode() }

  /// Deserialises a ``SignedMessage`` from CBOR bytes.
  public static func decode(_ bytes: [UInt8]) throws -> SignedMessage {
    let cbor: CBOR
    do { cbor = try CBOR.decode(bytes) } catch { throw DiemError.invalidCBOR }
    return try fromCBOR(cbor)
  }
}

// MARK: - SignedMessage
