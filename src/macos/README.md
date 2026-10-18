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

## Layout

- `Sources/CSealPDF` is a Clang module over `src/sealpdf-ffi/include/sealpdf.h`, the only copy of the header.
- `Sources/SealPDF/Certificates.swift` wraps the C calls and frees what Rust allocates.
- `SignModel.swift` holds the state and the open and save panels; `ContentView.swift` is the view and `PDFPreview.swift` the PDFKit preview.
