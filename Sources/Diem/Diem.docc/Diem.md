# ``Diem``

Portable identities: keys, signed messages, device-certified profiles and proofs.

## Overview

An identity is an identity key. The identity key certifies device keys, a certified
device signs the identity's profile content, and any certified device signs proofs of
application values on the identity's behalf.

```swift
var identity = try await BasicIdentity<ProfileRecord>(
  ProfileFields(domains: [DomainName("alice.example")]), using: backend)
try await identity.add(laptop.publicKey)
let proof = try await identity.prove(challenge)  // a Statement
try await proof.verify(against: identity.profile, using: backend)
```

### Records and applications

Every record is a canonical CBOR map; arrays contain lists only. Unsigned integer keys
are Diem's, and each record type exposes its field numbers as public static `cborKey…`
constants. Text keys are ``ApplicationID``s: reverse-DNS names such as
`com.example.notes`, each holding one application's field. Any other key type, or a text
key that is not a valid ID, is ``DiemError/invalidEncoding``. Required keys and types are
checked; unknown integer keys and every application field are accepted and retained when
a record is re-encoded. Applications write their fields in profile content, proofs and
device-link grants; other records only accept and retain them. ``CBOR/Record`` is the same shape for an application's own records. Tuple
encodings are not accepted, so identities and stored profiles require fresh state.

This is wire version 5: `Diem/profile` and `Diem/profile-content` are version 5 and
`Diem/proof` version 4. `Tests/Vectors/diem-v5.json` holds cross-language vectors, which
`Scripts/verify-vectors.ts` checks independently with WebCrypto.

### Profiles, identities and proofs

``Profile``, ``Identity`` and ``Proof`` are protocols. A profile is a signed
``ProfileRecord`` and the application ``Profile/Content`` decoded from it; the
application chooses the ``ProfileFields`` that publish new content. Those fields are
signed directly in the profile content: Diem's integer keys hold the content header and
the domains, and each application's field sits under its ID, at most
``ProfileFields/maximumApplications`` of them. ``ProfileRecord`` and ``ProofRecord`` are
the default profile and proof, with uninterpreted fields and value.

Several applications can share one identity's profile. A profile type names the
``Profile/applications`` whose fields its content owns. Every path that publishes content
(`init(publishing:…)`, `Identity.updating`, and `enrolling` with content) goes through
`fields(for:over:)`, which replaces the domains and the owned fields and keeps every
other application's field and any Diem content key newer than this version verbatim.
`renewing`, `adding`, `removing` and `enrolling` without content re-sign all current
fields unchanged. A future Diem field that must not be re-signed blindly will come with a
version bump instead. ``ProfileRecord``'s content is its complete fields, so publishing
it replaces them all.

A proof signs exactly one application's value under that application's ID. A
``Statement`` is an application's typed value: `identity.prove(statement)` signs it, and
``StatementProof`` decodes it, refusing a proof made for another application. Diem signs
statements without checking them; an application that checks a statement first wraps
`prove`, and `requireLive(until:window:)` is the shared check that a short-lived challenge
expires within a signing window.

Every profile signs the ``DomainName`` list that serves it. A ``DomainNamedProfile``
states how many domains its kind lists and how its content lists other domains
(`content(_:replacingDomains:)`), and a verifier that fetched a profile from a domain
checks that the profile serves that domain. Domains are lowercase DNS names; callers fold
user input with `DomainName(normalizing:)`.

`init(verifying:using:)` decodes a profile and verifies its certificates and signature at
its own `notBefore`, which accepts a profile that has since lapsed, such as one a device
stored earlier. Callers that need a current profile check `validity.contains(now)`.

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
There is no default algorithm. P-256 identity derivation is unsupported. These are recovery words, not a BIP 39 wallet seed.
`identityKey(matching:using:)` checks the derived key against a trusted profile.
`Tests/Vectors/identity-seed.json` holds cross-language vectors.

``SealedIdentitySeed`` encrypts the entropy to an encryption key for storage or transfer.
The record `{0:"Diem/sealed-identity-seed",1:1,2:identity,3:recipient,4:encapsulatedKey,5:ciphertext}`
binds keys 0–3 as both HPKE info and AAD. Opening re-derives and checks the identity.
Recovery words are the backup; applications own encrypted seed custody and consent.

`Profile.enrolling(_:identityKey:removing:publishing:profileLifetime:deviceLifetime:using:)`
certifies a fresh device with the recovered identity key and preserves the signed
revision chain. `removing` revokes listed device IDs in the same revision, advancing the
generation once and certifying only the final set, even at the 128-device limit. It
rejects unknown IDs and removal of the fresh signer. `publishing` optionally replaces
the content; otherwise its fields are preserved. The caller obtains the latest trusted
profile, enforces its version floor, retains and publishes the new revision. Device keys
stay on their creating device.
``KeyProtection/nonExportable`` describes platform-held keys such as non-extractable
WebCrypto keys without claiming hardware protection; ``KeyProtection/hardware`` remains
for hardware stores such as Secure Enclave.

## Linking a device

A new device joins an identity by QR code without the identity key leaving the approving
device, unless the approver chooses to transfer custody. The new device makes a
``DeviceLinkRequest`` (its device key, a P-256 recipient key, a display label and the
algorithms it can verify) and shows its ``DeviceLinkCode``, the request's digest and a
16-byte secret, as a QR code. The application chooses the QR URL and its parameter name;
Diem supplies the code's strict base64url `parameter`. The request itself travels over any
channel; the approver checks the received bytes with `matches(_:)` and calls
`requireCompatible(identityKey:device:)` before certifying the device and publishing the
new revision.

The approver then seals a ``DeviceLinkGrant``: the exact published profile, the domain it
was published at, optionally the ``SealedIdentitySeed`` sealed to the request's recipient,
and application fields under their IDs, which Diem does not interpret or restrict. A
``DeviceLinkResponse`` is the grant sealed with HPKE whose info and associated data are
the ``DeviceLinkContext``, so only the device that scanned the code can open it. Records
are tagged `Diem/device-link-request`, `-code`, `-context` and `-grant`, version 1;
requests, codes and contexts are bounded to 4,096 bytes and grants and responses to
65,536, and failures of these records are ``DiemError/invalidDeviceLink``.

`seal` and `open` decode the grant's profile as a caller-chosen ``DomainNamedProfile``
and verify it at the given time: its signatures and validity, that it lists the grant's
domain, that it certifies the request's device in its current generation with a
certificate valid at that time, that the new device can verify its keys' algorithms, and
that a sealed seed belongs to its identity and the request's recipient. Applications pass
their own acceptance rules, such as the kind of profile a device may join, as the
`accept` closure, which runs on the verified profile before any seed is opened.

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
- ``Statement``
- ``StatementProof``
- ``ApplicationID``

### Device linking

- ``DeviceLinkRequest``
- ``DeviceLinkCode``
- ``DeviceLinkContext``
- ``DeviceLinkGrant``
- ``DeviceLinkResponse``

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
- ``Base64URL``
- ``Digest``
- ``SHA2``
- ``Validity``
- ``DiemError``
