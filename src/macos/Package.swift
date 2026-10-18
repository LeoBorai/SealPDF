// swift-tools-version:5.9
import PackageDescription

// The Rust static library `libsealpdf_ffi` is not built here. `just dev-macos` builds it and
// passes its folder to the linker with `-Xlinker -L<folder>`.
let package = Package(
    name: "SealPDF",
    platforms: [.macOS(.v13)],
    targets: [
        .systemLibrary(name: "CSealPDF", path: "Sources/CSealPDF"),
        .executableTarget(
            name: "SealPDF",
            dependencies: ["CSealPDF"],
            path: "Sources/SealPDF",
            linkerSettings: [
                .linkedLibrary("sealpdf_ffi"),
                // What the Rust library itself uses for the Keychain.
                .linkedFramework("Security"),
                .linkedFramework("CoreFoundation"),
            ]
        ),
    ]
)
