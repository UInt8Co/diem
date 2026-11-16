# ``DiemProfileHosting``

Host signed Diem profiles and first-come name claims under one domain.

## Overview

A host assigns `<label>.<domain>` to the first identity that publishes a valid signed
profile listing it. It implements the server side of the contract that
`DiemProfileHostingClient` documents and shares that module's problem codes, proof
header grammar and proof-of-work puzzle, so both sides agree on every byte.

The module is built only with the package trait `ProfileHostingServer`; without it the
module is empty and `diem-profile-hosting` only reports how to build it. The trait keeps
Hummingbird, Fluent and SwiftNIO out of the dependency graph of applications that use
`Diem` or `DiemProfileHostingClient`:

```swift
.package(url: "https://github.com/UInt8Co/diem.git", revision: "<commit>",
  traits: ["ProfileHostingServer"])
```

### Serving

``DiemProfileHosting`` owns one SQLite database. Mount its
``DiemProfileHosting/middleware()`` outermost in a Hummingbird router: it answers every
request for the hosting domain or a name below it and passes all other hosts on. The
apex serves only the policy and name status; deeper names are not found. Alternatively,
``DiemProfileHosting/run(host:port:logger:)`` serves the module alone and drains requests
on SIGTERM or SIGINT before closing the database. Either way, the owner calls
``DiemProfileHosting/shutdown()`` once requests have drained.

The standalone executable takes the same JSON configuration:

```sh
swift build --traits ProfileHostingServer --product diem-profile-hosting
diem-profile-hosting --config hosting.json --host 127.0.0.1 --port 8080 --data-dir /var/lib/diem
```

Run it behind a TLS-terminating proxy that forwards the apex and wildcard hosts with
their `Host` header. `{"domain":"id.example"}` is a complete configuration.

### Configuration

``DiemProfileHostingConfiguration`` decodes the host's own JSON and refuses unknown keys.
Only `domain` is required; the type lists the limits, label pattern, expiry grace and
proof-of-work curve with their defaults. A relative `database` path resolves against the
data directory.

Every hosted name serves its profile at ``DiemProfileHosting/profilePath``. Applications
whose readers fetch another well-known path pass it in `profileAliases` (or
`--profile-alias`); the alias serves and accepts the same resource.

### Claims

A `PUT` of the profile to any hosted name it lists verifies it, claims every listed name
under the domain and stores it, in one transaction. A request that cannot claim every
name stores nothing. Each later revision replaces the identity's set of names, so a name
it drops is released at once; revisions must increase and device generations must not
decrease. A claim lapses only once the holder's profile has been expired for longer than
the grace period. New names need a proof of work whose difficulty rises as labels get
shorter; names already held need none. Updates per identity are limited over a rolling
hour.

### Apex hosts

A host that publishes its own domain's identity elsewhere can reuse
``HostingResponses``, `HostingProblem/response()` and
``HostingProofHeader/validateForApex(_:)`` to answer in the same wire format.

## Topics

### Hosting

- ``DiemProfileHosting``
- ``ProfileHostingMiddleware``
- ``DiemProfileHostingConfiguration``
- ``ConfigurationError``

### Apex hosts

- ``HostingResponses``
- ``HostingProofHeader``
