# SealPDF

Sign a PDF with the digital certificate installed on your computer. The signature is invisible: nothing is added to the pages, but the file is cryptographically signed, and earlier signatures in it stay valid.

```
sealpdf sign contract.pdf        # writes contract_signed.pdf
```

## Why "SealPDF"

A seal is the mark that closes a document and shows it has not been opened or changed since. Wax seals did this for letters, and a digital signature does it for a file: if a single byte covered by the signature changes, the seal breaks and verification fails. The tool puts that seal on a PDF, so the name is *seal* plus *PDF*. The command and the Rust crates are written in lowercase (`sealpdf`); the product is written *SealPDF*.

## Install

From a release (Linux and macOS, `x86_64` and `aarch64`):

```
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/LeoBorai/SealPDF/main/install.sh | sh
```

It installs to `~/.local/bin` (set `SEALPDF_INSTALL_DIR` to change that, `SEALPDF_VERSION=v0.1.0` to pick a release) and checks the SHA-256 of the download first. On Windows, download the `.zip` from the [releases page](https://github.com/LeoBorai/SealPDF/releases/latest).

From source:

```
cargo install --path src/cli      # installs the `sealpdf` command
```

On macOS there is also a window, a SwiftUI app: `just dev-macos` (see [src/macos](src/macos/README.md)).

Releases are built by `.github/workflows/release.yml` when a `vX.Y.Z` tag is pushed. The tag must match the workspace `version` in `Cargo.toml`.

## Use

List the signing certificates that are available:

```
sealpdf list-certs
```

Sign a PDF. With one certificate it is used; with several, you pick one from a numbered list:

```
sealpdf sign contract.pdf
```

The signed file is written next to the original as `contract_signed.pdf`; the original is never changed. Useful options:

```
sealpdf sign contract.pdf --alias "Ada Lovelace"   # choose the certificate by its alias
sealpdf sign contract.pdf --output signed/contract.pdf
sealpdf sign contract.pdf --force                  # replace an existing output file
```

Signing a PDF that is already signed adds one more signature and keeps the earlier ones valid.

### Where the certificate comes from

On macOS the default is your Keychain (`--keystore keychain`). macOS asks you to allow the use of the key, with your login password or Touch ID; sealpdf never sees that secret. Anywhere else, or for a certificate exported to a file, point to a PKCS#12 file:

```
sealpdf list-certs --keystore pkcs12:me.p12
sealpdf sign contract.pdf --keystore pkcs12:me.p12
```

SealPDF asks for the file's password each time, with no echo. It never stores a password or PIN. For scripts, name an environment variable that holds the password (never put the password itself on the command line):

```
P12_PASSWORD='...' sealpdf sign contract.pdf --keystore pkcs12:me.p12 --password-env P12_PASSWORD
```

### What it will not sign

Nothing is written, and SealPDF says why, when the PDF is encrypted (not supported yet), is certified so that no further changes are allowed, or is not a readable PDF.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 2 | The command was used wrongly (unknown option, output exists without `--force`, several certificates and no terminal to choose on) |
| 3 | The PDF was refused (encrypted, certified, unreadable) |
| 4 | A certificate, password or key access problem (wrong password, access declined, no such alias) |
| 6 | Anything else |

The full behaviour of each command, with diagrams, is in [docs/cli](docs/cli/README.md).

## Opening a signed PDF

A signature made with a certificate from a private or unknown authority is valid, but Adobe Acrobat shows "validity unknown" until it trusts the certificate's issuer. That is a trust setting, not a problem with the signature. Certificates from authorities in Adobe's trusted list show as valid.

## Not included yet

Visible signatures and text, timestamps, signature policies, certification levels, checking signatures (`verify`), signing encrypted PDFs, and smart card (PKCS#11) use from the command line. The plan for them is kept in `openspec/changes/rust-pades-signer-v1/deferred/`.

## Development

```
cargo nextest run --workspace
cargo deny check -D warnings   # advisories, licenses, duplicate versions, sources (config in deny.toml)
```

The tests build their certificates with the `openssl` command line tool and skip when it is missing. The PKCS#11 tests need SoftHSM2, and the interoperability tests need pyHanko (`pip install pyhanko`); both are required in CI. The macOS Keychain tests run only on macOS.

## Extra

### Validating a Signature

You can use the web based solution from the Spain Gov. to check on signatures.

https://firmaelectronica.gob.es/ciudadanos/cosas-deberias-saber/validacion-firmas#valide

Visit the site here: https://valide.redsara.es/valide/validarFirma/ejecutar.html
