# sealpdf-ffi

A C interface to SealPDF's signing and signature checking, for the SwiftUI app in `src/macos`. It builds as a static library (`libsealpdf_ffi.a`); the declarations are in `include/sealpdf.h`.

## Interface

1. `sealpdf_certs_open` lists the signing certificates of the macOS Keychain, and `sealpdf_certs_open_pkcs12` those of a `.p12` / `.pfx` file, like `sealpdf --keystore pkcs12:<file>`. Both keep the ones that pass the default `CertFilters`, the ones `sealpdf list-certs` shows, and return a handle.
2. `sealpdf_certs_count` and `sealpdf_certs_alias` read the list.
3. `sealpdf_sign` signs a PDF with a certificate chosen by alias and writes a new file. The input is never changed and may not be the output; a failure leaves no partial file. Signing a signed PDF adds one more signature.
4. `sealpdf_signature_count` says how many signatures a PDF carries (document timestamps not counted), without decoding any of them. It is what the **Sign** tab calls when a PDF is opened, to decide whether to show the "previously signed" notice. It returns `-1` with a message if the file is not a readable PDF.
5. `sealpdf_inspect` lists and checks the signatures of a PDF and returns the report as JSON: the text `sealpdf verify --json` prints, documented in [docs/cli/verify.md](../../docs/cli/verify.md). It is what the **Verify** tab calls, and only for a PDF opened or sent there. It returns null with a message if the file cannot be read, is not a PDF, or is encrypted. Call it off the main thread.
6. `sealpdf_certs_free` and `sealpdf_string_free` release what the library handed out, the strings and the JSON included.

Failures come back as a non-zero code or a null handle, with a message written through the `error` argument. A panic is caught and reported the same way; it never unwinds into the caller.

For the Keychain, macOS decides whether the key may be used and shows its own prompt (login password or Touch ID). For a file, the caller passes the file's password once, when opening; it is held as a wiped-on-drop secret and not kept after the file is opened. `sealpdf_sign` waits for that prompt, so call it off the main thread, and make one call at a time per handle.

On other systems the library builds, `sealpdf_certs_open_pkcs12` works, and `sealpdf_certs_open` fails with a message saying the Keychain is available only on macOS.

## `job`

`job::sign_file`, `job::offered`, `job::signature_count` and `job::inspect_json` hold the work behind the C functions and are tested on every platform.
