// swift-tools-version: 6.4
import PackageDescription

// Diem's browser runtime: a BridgeJS library that applications link into their own WASM,
// and a thin executable for the standalone `diem.wasm`. See README.md.
let package = Package(
  name: "DiemWeb",
  products: [
    // The generic `@JS` API and the Swift support an application's web executable reuses.
    .library(name: "DiemWeb", targets: ["DiemWeb"]),
    // The standalone runtime; build it with `node build.mjs`.
    .executable(name: "DiemWebRuntime", targets: ["DiemWebRuntime"]),
  ],
  dependencies: [
    .package(name: "Diem", path: ".."),
    .package(url: "https://github.com/swiftwasm/JavaScriptKit.git", revision: "777848dfd70279c34f885c0c2f9e2c3fc3a45698"),
  ],
  targets: [
    .target(
      name: "DiemWeb",
      dependencies: [
        .product(name: "Diem", package: "Diem"),
        .product(name: "DiemProfileHostingClient", package: "Diem"),
        .product(name: "JavaScriptKit", package: "JavaScriptKit"),
        .product(name: "JavaScriptEventLoop", package: "JavaScriptKit"),
      ],
      swiftSettings: [.enableExperimentalFeature("Extern")],
      plugins: [.plugin(name: "BridgeJS", package: "JavaScriptKit")]
    ),
    .executableTarget(
      name: "DiemWebRuntime",
      dependencies: [
        "DiemWeb",
        .product(name: "JavaScriptEventLoop", package: "JavaScriptKit"),
      ],
      // Embedded keeps Unicode tables optional; preserve Swift String semantics.
      linkerSettings: [
        .linkedLibrary("swiftUnicodeDataTables", .when(platforms: [.wasi])),
        .unsafeFlags(["-Xclang-linker", "-mexec-model=reactor", "-Xlinker", "--export-if-defined=__main_argc_argv"], .when(platforms: [.wasi])),
      ]
    ),
  ],
  swiftLanguageModes: [.v5]
)
