# certsign

Sign a PDF with the digital certificate installed on your computer. The signature is invisible: nothing is added to the pages, but the file is cryptographically signed, and earlier signatures in it stay valid.

```
certsign sign contract.pdf        # writes contract_signed.pdf
```

## Install

```
cargo install --path src/cli      # installs the `certsign` command
```

## Use

List the signing certificates that are available:

```
certsign list-certs
```

Sign a PDF. With one certificate it is used; with several, you pick one from a numbered list:

```
certsign sign contract.pdf
```

The signed file is written next to the original as `contract_signed.pdf`; the original is never changed. Useful options:

```
certsign sign contract.pdf --alias "Ada Lovelace"   # choose the certificate by its alias
certsign sign contract.pdf --output signed/contract.pdf
certsign sign contract.pdf --force                  # replace an existing output file
```

Signing a PDF that is already signed adds one more signature and keeps the earlier ones valid.

### Where the certificate comes from

On macOS the default is your Keychain (`--keystore keychain`). macOS asks you to allow the use of the key, with your login password or Touch ID; certsign never sees that secret. Anywhere else, or for a certificate exported to a file, point to a PKCS#12 file:

```
certsign list-certs --keystore pkcs12:me.p12
certsign sign contract.pdf --keystore pkcs12:me.p12
```

certsign asks for the file's password each time, with no echo. It never stores a password or PIN. For scripts, name an environment variable that holds the password (never put the password itself on the command line):

```
P12_PASSWORD='...' certsign sign contract.pdf --keystore pkcs12:me.p12 --password-env P12_PASSWORD
```

### What it will not sign

Nothing is written, and certsign says why, when the PDF is encrypted (not supported yet), is certified so that no further changes are allowed, or is not a readable PDF.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 2 | The command was used wrongly (unknown option, output exists without `--force`, several certificates and no terminal to choose on) |
| 3 | The PDF was refused (encrypted, certified, unreadable) |
| 4 | A certificate, password or key access problem (wrong password, access declined, no such alias) |
| 6 | Anything else |

## Opening a signed PDF

A signature made with a certificate from a private or unknown authority is valid, but Adobe Acrobat shows "validity unknown" until it trusts the certificate's issuer. That is a trust setting, not a problem with the signature. Certificates from authorities in Adobe's trusted list show as valid.

## Not included yet

Visible signatures and text, timestamps, signature policies, certification levels, checking signatures (`verify`), signing encrypted PDFs, and smart card (PKCS#11) use from the command line. The plan for them is kept in `openspec/changes/rust-pades-signer-v1/deferred/`.

## Development

```
cargo nextest run --workspace
cargo deny check        # dependency advisories, licenses and sources (config in deny.toml)
```

The tests build their certificates with the `openssl` command line tool and skip when it is missing. The PKCS#11 tests need SoftHSM2, and the interoperability tests need pyHanko (`pip install pyhanko`); both are required in CI. The macOS Keychain tests run only on macOS.
