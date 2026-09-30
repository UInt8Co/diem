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

### Keys

Every key serves one purpose, named in its encoding and therefore in its ID: an identity
key only certifies devices, a device key only signs profile content and proofs, and an
encryption key only opens what is sealed to it. Records accept a key only in the role its
``PublicKey/Purpose`` allows, and an identity refuses a device whose key material is its
own identity key.

New keys are post-quantum by default: ML-DSA-65 for signatures and X-Wing for encryption.
Ed25519, P-256 and X25519 remain for callers that choose them explicitly, such as
hardware-backed P-256 keys; they are not post-quantum.

A ``CryptoBackend`` supplies signatures, verification, encryption and the current time.
`DiemSwiftCrypto` provides one on Swift Crypto.

### Validity

Applications choose `profileLifetime` and `deviceLifetime` when creating or opening an
``Identity``. They control subsequent publication and certification by that instance.
Defaults remain one day for profiles and 30 days for certificates; those are defaults,
not protocol limits. Validity intervals must fit signed 64-bit Unix timestamps. Profile
content is bounded by its signing certificate, and only the identity key can extend
device certification. Verification checks the signed intervals at the requested time.

### Embedded Swift

The Foundation-free `Diem` target supports Swift 6.4 Embedded, including WebAssembly.
Supply a concrete ``CryptoBackend`` to identity initializers and verification methods
so the compiler can specialize their generic calls. The stored identity backend
remains type-erased. Platform cryptography belongs to the supplied backend;
`DiemSwiftCrypto` is a separate, non-Embedded integration.
Embedded executables using the CBOR decoder must link `swiftUnicodeDataTables` for
Swift's Unicode-aware text equality and hashing; unused table sections can be stripped.

## Recovering on another device

`Identity.enrolling(_:in:identityKey:profileLifetime:deviceLifetime:using:)` uses a
recovered identity key to certify a fresh device without copying the old device's
private key. It preserves existing devices and the signed revision chain. The caller
must obtain the latest trusted profile and enforce its saved version floor before
recovery, then retain and publish the new revision. Hardware device keys remain on
the device that created them; optional identity-key synchronization is application
custody policy, separate from device-key synchronization.

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
