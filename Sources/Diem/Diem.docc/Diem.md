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

An ``IdentitySeed`` is the identity root. Its 24 BIP 39 English recovery words encode
32 bytes of entropy and a checksum. Parsing ignores ASCII case and whitespace and
rejects an incorrect word count, unknown words or a failed checksum.

`identityKey(_:using:)` derives an Ed25519 or ML-DSA-65 identity key with HKDF-SHA256,
an empty salt, and canonical CBOR info `{0:"Diem/identity-seed",1:1,2:1,3:algorithm}`.
There is no default algorithm; Blah clients choose `.ed25519`. P-256 identity derivation
is unsupported. These are recovery words, not a BIP 39 wallet seed.
`identityKey(matching:using:)` checks the derived key against a trusted profile.
`Tests/Vectors/identity-seed.json` holds cross-language vectors.

``SealedIdentitySeed`` encrypts the entropy to an encryption key for storage or transfer.
The record `{0:"Diem/sealed-identity-seed",1:1,2:identity,3:recipient,4:encapsulatedKey,5:ciphertext}`
binds keys 0–3 as both HPKE info and AAD. Opening re-derives and checks the identity.
Recovery words are the backup; applications own encrypted seed custody and consent.

`Profile.enrolling(_:identityKey:profileLifetime:deviceLifetime:using:)` certifies a
fresh device with the recovered identity key, preserving existing devices and the signed
revision chain. The caller obtains the latest trusted profile, enforces its version
floor, retains and publishes the new revision. Device keys stay on their creating device.
``KeyProtection/nonExportable`` describes platform-held keys such as non-extractable
WebCrypto keys without claiming hardware protection; ``KeyProtection/hardware`` remains
for hardware stores such as Secure Enclave.

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
- ``IdentitySeed``
- ``SealedIdentitySeed``

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
