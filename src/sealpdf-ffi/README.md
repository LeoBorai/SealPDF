# sealpdf-ffi

A C interface to SealPDF's signing, for the SwiftUI app in `src/macos`. It builds as a static library (`libsealpdf_ffi.a`); the declarations are in `include/sealpdf.h`.

## Interface

1. `sealpdf_certs_open` lists the signing certificates of the macOS Keychain, and `sealpdf_certs_open_pkcs12` those of a `.p12` / `.pfx` file, like `sealpdf --keystore pkcs12:<file>`. Both keep the ones that pass the default `CertFilters`, the ones `sealpdf list-certs` shows, and return a handle.
2. `sealpdf_certs_count` and `sealpdf_certs_alias` read the list.
3. `sealpdf_sign` signs a PDF with a certificate chosen by alias and writes a new file. The input is never changed and may not be the output; a failure leaves no partial file. Signing a signed PDF adds one more signature.
4. `sealpdf_certs_free` and `sealpdf_string_free` release what the library handed out.

Failures come back as a non-zero code or a null handle, with a message written through the `error` argument. A panic is caught and reported the same way; it never unwinds into the caller.

For the Keychain, macOS decides whether the key may be used and shows its own prompt (login password or Touch ID). For a file, the caller passes the file's password once, when opening; it is held as a wiped-on-drop secret and not kept after the file is opened. `sealpdf_sign` waits for that prompt, so call it off the main thread, and make one call at a time per handle.

On other systems the library builds, `sealpdf_certs_open_pkcs12` works, and `sealpdf_certs_open` fails with a message saying the Keychain is available only on macOS.

## `job`

`job::sign_file` and `job::offered` hold the work behind the C functions and are tested on every platform.
