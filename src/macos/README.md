# macos

The macOS window for SealPDF, written in SwiftUI. It is a Swift package that runs from the command line; the signing is done by the Rust library in `src/sealpdf-ffi`, through its C interface.

```sh
just dev-macos
```

That builds `libsealpdf_ffi.a` with `cargo`, then runs `swift run` with the library's folder on the linker path. It needs macOS and the Xcode command line tools.

## The window

Two tabs, **Sign** and **Verify**. Each has its own controls on the left and its own preview of the PDF (PDFKit) on the right, which you can scroll and zoom. Drop a PDF on a preview to open it there.

### Sign

1. **Open PDF…** takes a PDF. If it already carries a signature, a short notice says so: *This PDF was previously signed, go to Verify for details*. Following it opens the same PDF on the Verify tab. Signing stays available.
2. **Certificate** is either the **Keychain**, with its signing identities (the ones `sealpdf list-certs` shows), or a **File**: choose a `.p12` / `.pfx`, type its password and press **Unlock**. This is the window's `sealpdf sign --keystore pkcs12:<file>`. The password is used once to open the file and is then cleared.
3. **Visible signature** is off by default: the signature is then invisible and the pages are not touched. Turned on, the preview shows a box on the page, which starts where `sealpdf sign --visible` puts it (a 200 x 50 point box in the lower-left corner of the last page, asked from the Rust library so the two never differ) and scrolls into view. Drag the box to move it, or a corner to resize it (least size 40 x 20 points). It stays inside the visible area of the page, and it belongs to the page under its center when you drop it. Dropped over no page, it goes back where it was. Opening another PDF puts it back at its default place. The signature then shows AutoFirma's text, "Firmado por … el día … con un certificado emitido por …", with the date in this computer's time zone; the text cannot be changed yet. **Sign…** waits until the box is found.
4. **Sign…** asks where to save (it proposes `<name>_signed.pdf` next to the original) and signs. The original is never changed.

The box is kept in PDF page space (points, origin at the bottom-left of the page, the space of a PDF's `/Rect`), never in view space, and the overlay's frame is derived from it whenever the zoom, scroll or layout changes, so it stays on the same part of the page. PDFKit's `convert` handles page rotation. `sealpdf_sign_visible` receives the page and that rectangle.

For the Keychain, macOS asks to use the key with its own prompt (login password or Touch ID). Signing and unlocking run off the main thread, so the window stays responsive.

The notice only counts the signatures (`sealpdf_signature_count`); it checks none of them.

### Verify

**Open PDF…** takes a PDF and checks its signatures, like `sealpdf verify`. Nothing is checked until a PDF is opened on this tab, or sent to it from the Sign tab. The tab shows:

- the **verdict**: *Signed and intact* for `OK`, or the `KO` / `UNKNOWN` items with what each means;
- one entry per **signature**: the signer, the signing time, the revision it covers, and *Intact* or what is wrong;
- *This PDF is not signed.* when there is no signature;
- the reason, instead of a report, when the file is not a readable PDF or is encrypted;
- always the line *Certificate trust and revocation were not checked.* A signature can be intact and still come from someone you do not trust.

The check runs off the main thread (`sealpdf_inspect`). The meaning of each item is in [docs/cli/verify.md](../../docs/cli/verify.md).

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
- `Sources/SealPDF/Certificates.swift` wraps the C calls and frees what Rust allocates. `SignatureBox.swift` holds `PlacedBox` and the call for the default box, and `SignatureBoxOverlay.swift` the box drawn over the preview and the code that keeps it on its page.
- `AppInfo.swift` and `AboutView.swift` are the About window.
- `Resources/icon.icns` is the app icon.
- `Scripts/` holds the macOS scripts: `bundle.sh` makes the `.app` (from `Info.plist.template`), and `icons.sh` turns a PNG into an `.icns`.
- `ContentView.swift` holds the two tabs. `SignModel.swift` has the Sign tab's state and its open and save panels, and `SignView.swift` its view.
- `VerifyModel.swift` and `VerifyView.swift` are the Verify tab; `Report.swift` decodes the JSON that `sealpdf_inspect` returns and wraps the two inspection calls.
- `PDFPreview.swift` is the PDFKit preview and the pane (with its drop target) both tabs use.
