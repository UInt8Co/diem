# ``Diem``

Portable identities: keys, signed messages, device-certified profiles and proofs.

## Overview

An identity is an identity key. The identity key certifies device keys, a certified
device signs the identity's profile content, and any certified device signs proofs of
data on the identity's behalf. Every record is a canonical CBOR map with unsigned integer keys; arrays contain lists
only. Each record type exposes its field numbers as public static `cborKey…` constants.
Required keys and types are checked, and unknown integer keys are accepted.
Signed envelopes and public keys retain extension fields when re-encoded. Tuple
encodings are not accepted, so identities and stored profiles require fresh state.

```swift
var identity = try await BasicIdentity<ProfileRecord>(
  ProfileFields(domains: [DomainName("alice.example")]), using: backend)
try await identity.add(laptop.publicKey)
let proof = try await identity.prove(challenge)
try await proof.verify(against: identity.profile, using: backend)
```

### Profiles, identities and proofs

``Profile``, ``Identity`` and ``Proof`` are protocols. A profile is a signed
``ProfileRecord`` and the application ``Profile/Content`` decoded from it; the
application chooses the ``ProfileFields`` that publish new content. Those fields are
signed directly in the profile content: Diem keeps content keys below
``ProfileFields/firstApplicationKey`` and the application owns the rest, so application
profiles need no nested record of their own. ``ProfileRecord`` and ``ProofRecord`` are
the default profile and proof, with uninterpreted fields and data.

Every profile signs the ``DomainName`` list that serves it. A ``DomainNamedProfile``
states how many domains its kind lists, and a verifier that fetched a profile from a
domain checks that the profile serves that domain. Domains are lowercase DNS names;
callers fold user input with `DomainName(normalizing:)`.

An ``Identity`` supplies a device's keys and current profile. Its operations sign and
return the next revision without storing it, so storage-backed identities adopt a
revision only once it is durable. ``BasicIdentity`` adopts each revision it publishes.

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

Applications can export a software identity's recovery secret through
``IdentityPrivateKey/rawRepresentation`` and restore it with
``CryptoBackend/makePrivateKey(_:for:restoring:)`` using the same algorithm and the
identity purpose. Hardware identity keys cannot be exported or sealed.

`Profile.enrolling(_:identityKey:profileLifetime:deviceLifetime:using:)` uses a
recovered identity key to certify a fresh device without copying the old device's
private key. It preserves existing devices and the signed revision chain. The caller
must obtain the latest trusted profile and enforce its saved version floor before
recovery, then retain and publish the new revision. Hardware device keys remain on
the device that created them; optional identity-key synchronization is application
custody policy, separate from device-key synchronization.

## Paper device keys

A ``PaperDeviceKey`` is a software device key written down as 24 BIP 39 English words.
The words carry 256 bits of entropy and a checksum. Each algorithm's device seed is
HKDF-SHA256 of that entropy under a canonical derivation context, so the words are not a
BIP 39 wallet seed. The identity key certifies the paper's public key like any other
device, and removing it works the same way. Renewal with the identity key keeps it
certified; if nothing renews it, it expires with its certificate.

To use the paper, decode the words and fetch the identity's current profile.
`deviceKey(listedIn:using:)` derives a key only for the algorithms that profile lists and
returns the one it certifies. Like every device key, the paper signs proofs and profile
content but cannot certify devices or recover the identity key. Ed25519 and ML-DSA-65
papers are supported; P-256 belongs in hardware. `Tests/Vectors/paper-device-key.json`
holds cross-language vectors.

## Topics

### Identities

- ``Identity``
- ``BasicIdentity``
- ``Profile``
- ``ProfileRecord``
- ``ProfileFields``
- ``DomainNamedProfile``
- ``DomainName``
- ``DeviceCertificate``
- ``Proof``
- ``ProofRecord``

### Identity and device keys

- ``IdentityPublicKey``
- ``IdentityPrivateKey``
- ``DevicePublicKey``
- ``DevicePrivateKey``
- ``PaperDeviceKey``
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
