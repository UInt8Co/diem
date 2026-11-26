# ``DiemTesting``

Test doubles for Diem and its applications: a clock you control and an in-memory profile host.

## Overview

``TestBackend`` is `SwiftCryptoBackend` with a clock that starts at
``TestBackend/start`` (1,800,000,000) and moves only when a test calls
``TestBackend/advance(by:)``, so validity periods and expiry are deterministic.

``FakeProfileHost`` is a `HostingHTTPClient` that answers as a profile host at
`id.example` would, with child names and the apex. Its wire handling is written
independently of `DiemProfileHostingClient`, so tests exercise the documented wire format.

The module uses Foundation and Swift Crypto. It is for tests only and is not Embedded.

## Topics

- ``TestBackend``
- ``FakeProfileHost``
