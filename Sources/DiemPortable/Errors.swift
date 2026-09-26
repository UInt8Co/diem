public enum DiemError: Error, Sendable, Equatable {
  case keyNotFound, invalidKeyType, invalidCBOR, invalidKey
  case missingField(String)
  case encryptionFailed, decryptionFailed, alreadyExists, verificationFailed
  case unexpectedMessageRecipientType
  case unsupportedAlgorithm(KeyAlgorithm)
  case roleConfusion
}
