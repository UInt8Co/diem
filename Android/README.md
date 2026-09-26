# Android device keys

`AndroidDeviceKeys` supplies separate destination-generated P-256 signing and wrapping
keys from Android Keystore (API 31 or later). Persist only the alias prefix. Its public
keys use SEC1 uncompressed encoding, signing uses IEEE P1363, and envelope opening uses
the same RFC 9180 suite and authenticated context as Diem's Swift P-256 backend.
The application bridge implements `DeviceSigningKey`/`DeviceWrappingKey` using these
operations; identity, profile and enrollment policy lives in BlahDiem.

Request StrongBox explicitly when required. Creation fails if the requested backend or
key purpose is unavailable. Read the protection level for **both** keys; Keystore alone
does not imply hardware. If the user approves software fallback, generate fresh software
keys and display that protection level. Do not import a key and label it hardware-created.
Keys that require per-operation authentication must be used through the application's
biometric authorization flow. Keep controller envelopes in private, independently backed
up storage and explain permanent root trust before controller promotion.

BlahDiem's `Scripts/verify-hpke-vectors.ts` checks the receiver against Swift Crypto ciphertexts and
rejects context/key substitution. It needs a Java 17+ JDK and Deno. This exercises JCA
software, not Android hardware. The instrumentation test must additionally run on real
TEE/StrongBox devices before release; emulator success is not evidence of hardware custody.

Build the library with Gradle 8.11.1 (`gradle -p Android assembleDebug`) and run
`gradle -p Android connectedDebugAndroidTest` with a physical API 31+ device attached.
