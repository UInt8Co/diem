# Android device keys

`AndroidDeviceKeys` supplies destination-generated P-256 signing and encryption keys from
Android Keystore (API 31 or later). Persist only the alias prefix. Its public keys use SEC1
uncompressed encoding, signing uses IEEE P1363, and opening uses the same RFC 9180 suite
and authenticated context as Diem's P-256 backend. An application backend wraps these
operations as Diem `PrivateKey` and `EncryptionPrivateKey` values with hardware protection.

Request StrongBox explicitly when required. Creation fails if the requested backend or key
purpose is unavailable. Read the protection level of **both** keys, and report software
keys as software. Keys that require per-operation authentication are used through the
application's biometric authorization flow.

`Scripts/verify-hpke-vectors.ts` opens Swift-sealed identity keys with this receiver and
checks that it rejects context and key substitution. It needs a Java 17+ JDK and Deno, and
exercises JCA software. The instrumentation test covers real TEE/StrongBox devices.

Build the library with Gradle 8.11.1 (`gradle -p Android assembleDebug`) and run
`gradle -p Android connectedDebugAndroidTest` with a physical API 31+ device attached.
