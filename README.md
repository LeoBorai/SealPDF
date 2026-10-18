<div>
  <p align="center">
    <img src="docs/icon.png" alt="SealPDF" width="128" height="128" />
  </p>
  <h1 align="center">SealPDF</h1>
  <h4 align="center">
    PDF Digital Signature Tool. Sign a PDF with the certificate installed on your computer,
    from the command line or from a macOS app.
  </h4>
</div>

<div align="center">

  [![Release](https://img.shields.io/github/v/release/LeoBorai/SealPDF)](https://github.com/LeoBorai/SealPDF/releases/latest)
  [![CI](https://github.com/LeoBorai/SealPDF/actions/workflows/ci.yml/badge.svg)](https://github.com/LeoBorai/SealPDF/actions/workflows/ci.yml)

</div>

> SealPDF is under development. Features and options may change between releases.

The signature is invisible: nothing is added to the pages, but the file is cryptographically signed, and earlier signatures in it stay valid. The original file is never changed.

A seal is the mark that closes a document and shows it has not been opened or changed since. A digital signature does the same for a file: if a single byte covered by the signature changes, the seal breaks and verification fails.

## Usage

```sh
sealpdf sign contract.pdf        # writes contract_signed.pdf
```

With one certificate it is used; with several, you pick one from a numbered list. To sign with a certificate file instead of the installed ones:

```sh
sealpdf sign contract.pdf --keystore pkcs12:me.p12
```

<details>
  <summary>More options</summary>

```sh
sealpdf list-certs                                  # the certificates available for signing
sealpdf sign contract.pdf --alias "Ada Lovelace"    # choose the certificate by its alias
sealpdf sign contract.pdf --output signed/contract.pdf
sealpdf sign contract.pdf --force                   # replace an existing output file
P12_PASSWORD='...' sealpdf sign contract.pdf --keystore pkcs12:me.p12 --password-env P12_PASSWORD
```

On macOS the default is your Keychain (`--keystore keychain`). macOS asks you to allow the use of the key, with your login password or Touch ID; SealPDF never sees that secret. For a PKCS#12 file SealPDF asks for the password each time, with no echo, and never stores a password or PIN. Never put a password on the command line: name an environment variable with `--password-env`.

Signing a PDF that is already signed adds one more signature and keeps the earlier ones valid. Nothing is written, and SealPDF says why, when the PDF is encrypted (not supported yet), is certified so that no further changes are allowed, or is not a readable PDF.

| Exit code | Meaning |
| --- | --- |
| 0 | Success |
| 2 | The command was used wrongly |
| 3 | The PDF was refused (encrypted, certified, unreadable) |
| 4 | A certificate, password or key access problem |
| 6 | Anything else |

The full behaviour of each command, with diagrams, is in [docs/cli](docs/cli/README.md).

</details>

## Install

From a release (Linux and macOS, `x86_64` and `aarch64`):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/LeoBorai/SealPDF/main/install.sh | sh
```

It installs to `~/.local/bin` (set `SEALPDF_INSTALL_DIR` to change that, `SEALPDF_VERSION=v0.1.0` to pick a release) and checks the SHA-256 of the download first. On Windows, download the `.zip` from the [releases page](https://github.com/LeoBorai/SealPDF/releases/latest).

From source:

```sh
cargo install --path src/cli      # installs the `sealpdf` command
```

## macOS app

Every release includes `SealPDF.app` for Apple Silicon: open a PDF, preview it, choose a certificate from the Keychain or a `.p12` file, and sign.

```sh
just dev-macos        # run the app
just bundle-macos     # make target/macos/SealPDF.app
```

See [src/macos](src/macos/README.md).

## Opening a signed PDF

A signature made with a certificate from a private or unknown authority is valid, but Adobe Acrobat shows "validity unknown" until it trusts the certificate's issuer. That is a trust setting, not a problem with the signature.

To check a signature, you can use the [validation service](https://valide.redsara.es/valide/validarFirma/ejecutar.html) of the Spanish Government ([more information](https://firmaelectronica.gob.es/ciudadanos/cosas-deberias-saber/validacion-firmas#valide)).

## Not included yet

Visible signatures and text, timestamps, signature policies, certification levels, checking signatures (`verify`), signing encrypted PDFs, and smart card (PKCS#11) use from the command line. The plan for them is kept in `openspec/changes/rust-pades-signer-v1/deferred/`.

## Development

```sh
cargo nextest run --workspace
cargo deny check -D warnings   # advisories, licenses, duplicate versions, sources (config in deny.toml)
```

The tests build their certificates with the `openssl` command line tool and skip when it is missing. The PKCS#11 tests need SoftHSM2, and the interoperability tests need pyHanko (`pip install pyhanko`); both are required in CI. The macOS Keychain tests run only on macOS.

## Release

Releases are built by `.github/workflows/release.yml` when a tag is pushed. The tag must be `v` followed by the workspace `version` in `Cargo.toml`.

```sh
git tag -a v0.1.4 -m "Release v0.1.4"
git push origin main --follow-tags
```

## Contributing

Every contribution to this project is welcome. Feel free to open a pull request, an issue or just by starring this project.
