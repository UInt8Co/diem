/// Errors produced by Diem cryptographic operations.
public enum DiemError: Error, Sendable, Equatable {
  /// No key matching the required key ID was found.
  case keyNotFound
  /// The key's type does not satisfy the operation (e.g. signing key used for encryption).
  case invalidKeyType
  /// The CBOR data is malformed or missing required structure.
  case invalidCBOR
  /// A required field is absent from serialised data.
  case missingField(String)
  /// The raw key bytes are invalid or have the wrong length.
  case invalidKey
  /// Encryption (or signing) failed.
  case encryptionFailed
  /// Decryption failed — wrong key, tampered ciphertext, or mismatched recipient.
  case decryptionFailed
  /// The backend does not support the requested crypto set.
  case unsupportedCryptoSet(CryptoSet)
  /// An item with this ID already exists in the store.
  case alreadyExists
  /// Signature verification failed — the message was not signed by the expected key.
  case verificationFailed
  /// The message recipient type does not match what was expected (key vs share).
  case unexpectedMessageRecipientType
}
