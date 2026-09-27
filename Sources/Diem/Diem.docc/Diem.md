# ``Diem``

Portable identities: keys, signed messages, device-certified profiles and proofs.

## Overview

An identity is an identity key. The identity key certifies device keys, a certified
device signs the identity's profile content, and any certified device signs proofs of
data on the identity's behalf. Every record is canonical CBOR, so its bytes are its identity.

```swift
var identity = try await Identity(data: profileData, using: backend)
try await identity.add(laptop.publicKey)
let proof = try await identity.prove(challenge)
try await proof.verify(against: identity.profile, using: backend)
```

A ``CryptoBackend`` supplies signatures, verification, encryption and the current time.
`DiemSwiftCrypto` provides one on Swift Crypto.

## Topics

### Identities

- ``Identity``
- ``Profile``
- ``DeviceCertificate``
- ``Proof``

### Identity and device keys

- ``IdentityPublicKey``
- ``IdentityPrivateKey``
- ``DevicePublicKey``
- ``DevicePrivateKey``
- ``SealedIdentityKey``

### Cryptographic primitives

- ``PublicKey``
- ``PrivateKey``
- ``SignedMessage``
- ``EncryptionPublicKey``
- ``EncryptionPrivateKey``
- ``SealedBox``
- ``KeyProtection``
- ``CryptoBackend``

### Encoding

- ``CBOR``
- ``Digest``
- ``SHA2``
- ``Validity``
- ``DiemError``
