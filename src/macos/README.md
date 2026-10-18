# macos

The macOS window for SealPDF, written in SwiftUI. It is a Swift package that runs from the command line; the signing is done by the Rust library in `src/sealpdf-ffi`, through its C interface.

```sh
just dev-macos
```

That builds `libsealpdf_ffi.a` with `cargo`, then runs `swift run` with the library's folder on the linker path. It needs macOS and the Xcode command line tools.

## The window

On the left, the controls; on the right, a preview of the PDF (PDFKit), which you can scroll and zoom. Drop a PDF on the preview to open it.

1. **Open PDF…** takes a PDF.
2. **Certificate** is either the **Keychain**, with its signing identities (the ones `sealpdf list-certs` shows), or a **File**: choose a `.p12` / `.pfx`, type its password and press **Unlock**. This is the window's `sealpdf sign --keystore pkcs12:<file>`. The password is used once to open the file and is then cleared.
3. **Sign…** asks where to save (it proposes `<name>_signed.pdf` next to the original) and signs. The original is never changed.

For the Keychain, macOS asks to use the key with its own prompt (login password or Touch ID). Signing and unlocking run off the main thread, so the window stays responsive.

## About window

**SealPDF > About SealPDF** shows the app icon, the name, "PDF Digital Signature Tool", the version, the commit it was built from (a link to that commit) and a **GitHub** button for the repository. The version and commit are written into `Info.plist` by `Scripts/bundle.sh`; from `just dev-macos` there is no bundle, so the version reads `dev` and the commit row is hidden.

## The app bundle

```sh
just bundle-macos      # builds, then writes target/macos/SealPDF.app
```

`Scripts/bundle.sh` copies the release executable into `SealPDF.app`, fills `Info.plist.template` (the version from the workspace `Cargo.toml`, the commit from `APP_COMMIT` or `HEAD`) and signs it ad hoc, so macOS lets it launch on Apple Silicon. There is no Developer ID: on first launch right-click > Open. The app icon is `Resources/icon.icns` (`Scripts/icons.sh` makes one from a PNG); the About window shows it too, once the app is bundled. Without that file the app gets the generic icon.

CI builds and checks the bundle on every push (`macos-app` in `ci.yml`). A release tag adds `SealPDF-<tag>-macos-aarch64.zip` (and its SHA-256) to the release, built from the release commit. Apple Silicon only.

## Layout

- `Sources/CSealPDF` is a Clang module over `src/sealpdf-ffi/include/sealpdf.h`, the only copy of the header.
- `Sources/SealPDF/Certificates.swift` wraps the C calls and frees what Rust allocates.
- `AppInfo.swift` and `AboutView.swift` are the About window.
- `Resources/icon.icns` is the app icon.
- `Scripts/` holds the macOS scripts: `bundle.sh` makes the `.app` (from `Info.plist.template`), and `icons.sh` turns a PNG into an `.icns`.
- `SignModel.swift` holds the state and the open and save panels; `ContentView.swift` is the view and `PDFPreview.swift` the PDFKit preview.
