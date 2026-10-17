# certsign-keystore

Access to signing keys and certificate chains through a `KeyStore` trait, without ever handing the private key to the caller. Backends: PKCS#12 files and PKCS#11 tokens.

## Traits

- `KeyStore` lists `Entry` values (an alias and a certificate chain, end-entity first) and signs data with the key of an alias. The store does the private-key operation itself and returns only the signature: PKCS#1 v1.5 for RSA, a DER `ECDSA-Sig-Value` for ECDSA.
- `AuthPrompt` is where a store gets the secret it needs: a file's password when it is opened, a token's PIN when something is signed (and not before). A terminal, an environment variable or a dialog can implement it. `StaticPrompt` and `NoPrompt` cover tests and callers that already hold, or refuse to supply, a secret.

## Secrets

Secrets cross the API as `SecretString`: wiped from memory when dropped and absent from `Debug` output. Backends that need a secret in another encoding (PKCS#12 derives its keys from a null-terminated UTF-16 big-endian password) hold it in `SecretBytes`, which is wiped on drop or on demand. Key store failures, wrong passwords and PINs included, are `KeystoreError` values, so a caller can tell a bad PIN (with the retries left, when the token says) from a missing secret.

## PKCS#12

`Pkcs12KeyStore` opens `.p12` / `.pfx` files. It asks the `AuthPrompt` for the file's password once, when opening; after that listing and signing need nothing more. Opening checks the file's MAC, so a wrong password fails the whole open with `KeystoreError::BadPassword` and no entries are listed. Both the current encryption (PBES2 with AES) and the older 3DES and RC2 schemes are read.

Each entry that has a private key is listed with its chain from the end-entity certificate to the root. Signing works with RSA keys (PKCS#1 v1.5, SHA-256, SHA-384 or SHA-512) and EC keys on P-256 and P-384 (ECDSA, any of those digests). Asking for a mismatched algorithm, an unsupported curve or an unknown alias is an error, never a silent fallback.

## PKCS#11

`Pkcs11KeyStore` uses a token (a smart card, an HSM, the Spanish DNIe through OpenSC) through a PKCS#11 module. The private key never leaves the token.

- **Module.** Give the module path, or an empty path for the OpenSC module in its usual place on this system (`default_module_candidates` lists where it looks for Linux, macOS and Windows). One library handle is kept per module path for the life of the process, because PKCS#11 modules are initialized once per process.
- **Slot.** With one token present it is used; with several, a slot has to be named, and the error lists the choices.
- **Listing needs no PIN.** Certificates are public objects. A certificate counts as a signing identity when the token shows a private key with the same `CKA_ID`; many tokens hide private keys until login, and then every certificate that is not a CA is offered. The chain is followed through the other certificates on the token.
- **Signing logs in lazily.** The user PIN is requested from the `AuthPrompt` only when something is signed, and the session logs out afterwards. RSA signs with `CKM_RSA_PKCS` over a `DigestInfo` (SHA-256, SHA-384 or SHA-512); ECDSA signs with `CKM_ECDSA` and the token's raw `r || s` is converted to DER.
- **PIN errors.** A wrong PIN is `KeystoreError::BadPin`. PKCS#11 has no retry counter, only the token's `FINAL_TRY` flag, so one try left is reported when the flag is set and nothing otherwise. A locked PIN is an error that says so.
