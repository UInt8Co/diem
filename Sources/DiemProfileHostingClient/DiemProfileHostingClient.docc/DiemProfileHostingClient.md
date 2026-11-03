# ``DiemProfileHostingClient``

Claim names and publish signed Diem profiles through an injected HTTP transport.

## Overview

A hosting domain may assign `<label>.<domain>` first come, first served and/or serve
its own domain (the apex). One PUT to a listed name publishes the identity's complete signed profile and replaces all its
claims under that hosting domain atomically. If any name fails, the whole request
fails. Availability and ownership plans are hints; the server decides publication.

```swift
let host = ProfileHostingClient(domain: try DomainName("id.example"), http: transport)
let solver = PortableProofOfWorkSolver()
let claim = try await identity.claiming(labels: ["alice"], at: host, solver: solver) {
  content, domains in ProfileFields(domains: domains, application: content.application)
}
// Store claim.profile durably, then publish it; retry the same bytes if unanswered.
try await host.publish(claim, solver: solver)
```

### Claim, update and release

``ProfileHostingClient/policy()`` reads the hosting policy. `policy.apex` indicates
apex support (absent on the wire means false); `policy.servesChildNames` indicates child-name
support. The optional `policy.names` groups the label pattern, claim, update and expiry-grace
limits and proof parameters: all child-name fields must be present or all absent. A policy
with neither capability is invalid. The pattern is informational; the server checks it.
Label APIs (`name`, `plan`, `prove`, `claiming`, `releasing`, string `via` and `profile(at:)`)
accept lowercase DNS child labels or the reserved apex label `@`. `labels(in:)` includes
`@` in signed domain order. Existing signatures remain unchanged.
``ProfileHostingClient/name(_:)`` reads availability (`…/hosting/names/@` for the apex).
Planning distinguishes invalid,
taken, held and new names. A held-name hint compares the fetched profile's identity ID;
it does not verify the profile's signatures or validity.

`identity.claiming(labels:at:solver:transform:)` plans and solves new names, appends
those domains to the existing list and signs the next revision with `identity.updating`.
The transform must return content with exactly the supplied domains. It returns a
``HostingPublication`` and publishes nothing. Store its profile before
``ProfileHostingClient/publish(_:solver:)``: a host accepts only later revisions than
the one it holds, and an identical PUT succeeds again, so an unanswered request is
retried with the stored bytes.

The host decides which names require proof. Use
``ProfileHostingClient/publish(_:via:proofs:)`` for one PUT, or
``ProfileHostingClient/publish(_:via:proofs:solver:)`` to try publication first and retry once
on `proof-required`, solving exactly the server's listed labels. Other refusals are
returned as ``ProfileHostingError/problem(_:)``; rate limits include Retry-After seconds.
A successful reply must identify the submitted identity and revision.

Publication defaults to the first listed child name of this host, falling back to the
apex when no child is listed and the profile lists the host's domain. Use
`host.publish(profile, via: .apex)` to explicitly choose the apex, including when child
names are also listed. `HostingTarget.name("alice")` explicitly selects a child; the
existing string `via: "alice"` overloads also remain available. `HostingPublication.via`
is an optional `HostingTarget`; nil uses the default selection. Apex publication uses
`PUT https://<domain>/.well-known/diem/profile.cbor`. Apex proofs use `@` in the proof
header and puzzle, with the same solve-and-retry flow as child names. Required bits for
`@` must be explicit in name status or proof-required problems; missing values throw
`.unsolvable("@")`. `policy.requiredBits(for: "@")` always returns nil.

For discovery, try the identity's first domain's policy for apex support first. Otherwise,
try its parent's policy for child-name support; otherwise use manual HTTPS publication.
Unavailable or invalid/mismatched policies move on to the next step. Store the chosen
hosting domain; equality with the identity's first domain represents apex publication.

`identity.releasing(labels:at:transform:)` signs a revision without those hosted names,
to be published through a retained name. Releasing every hosted name sends the new
revision through a removed, currently held name. `labels: ["@"]` removes the host's own
domain, with the same retained-name selection and release behavior as child names.
The low-level `via` parameter supports that same flow;
a removed name cannot be the request host while other hosted names remain listed.

### Caller responsibilities

Supply a concrete ``HostingHTTPClient`` for fetch, URLSession or another platform
transport. It must never follow redirects or send cookies or credentials, must enforce
a timeout and response size bound while receiving data, and must propagate cancellation.
The client also rejects responses over 262,144 bytes. JSON parsing is limited to 16
nested levels, rejects duplicate keys and malformed UTF-8, and reads schema integers
exactly without floating-point conversion. Unknown object fields are accepted.

`host.profile(at: "alice")` and `host.profile(at: .apex)` return raw CBOR or nil on 404.
The apex GET uses the same URL as its PUT. Callers that trust
a discovered profile must verify it with their Diem `CryptoBackend`, including validity
and that its signed domain list serves the requested name. Signing remains with Diem's
`Identity` and backend. Applications retain their revision floors and decide when to
adopt successfully published revisions.

Supply a ``ProofOfWorkSolver`` for native or parallel hashing when work is expensive.
``PortableProofOfWorkSolver`` is a fallback using Diem's SHA-256. It checks cancellation
and yields every 1,024 attempts, throwing ``ProfileHostingError/cancelled`` when cancelled.
The client checks each solver result before sending it. Transport and custom solver
errors propagate unchanged.

### Proof wire contract

The hash is SHA-256 of these concatenated bytes:

```
UTF8("diem-profile-hosting-pow-v1\0" + domain + "\0" + label + "\0")
  || identityID (32 bytes) || nonce (1...64 bytes)
```

It must have at least `requiredBits` leading zero bits. For child labels only, policy fallback computes:

```
baseBits + bitsPerShorterCharacter * max(0, referenceLength - label.utf8.count)
```

Arithmetic uses signed 64-bit values on every platform. Overflow or a result outside
0...64 is unsolvable. Mean work is approximately 2^requiredBits attempts. The portable
solver tries eight-byte big-endian counters starting at zero. Proofs are sent as
`Diem-Hosting-Proof: @=<nonce>, alice=<nonce>, bob=<nonce>` with sorted labels and
unpadded base64url. The apex uses `label = "@"` and only host-supplied required bits.

### Embedded Swift

This Foundation-free target depends only on `Diem` and supports Swift 6.4 Embedded
WebAssembly. Supply concrete HTTP and solver types so generic calls can specialize.
As with Diem's CBOR decoder, linked executables need `swiftUnicodeDataTables` for text
equality and hashing. No networking, platform cryptography or worker pool is built in.

## Topics

### Hosting

- ``ProfileHostingClient``
- ``HostingPublication``
- ``HostingTarget``
- ``HostingPolicy``
- ``HostedName``
- ``HostingPlan``
- ``HostingProblem``
- ``ProfileHostingError``

### Transport

- ``HostingHTTPClient``
- ``HostingHTTPRequest``
- ``HostingHTTPResponse``

### Proof of work

- ``ProofOfWorkPuzzle``
- ``ProofOfWorkSolver``
- ``PortableProofOfWorkSolver``
- ``hostingProofHeader(_:)``
