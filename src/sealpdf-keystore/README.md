# sealpdf-keystore

Access to signing keys and certificate chains through a `KeyStore` trait, without ever handing the private key to the caller. Backends: the macOS Keychain, PKCS#12 files and PKCS#11 tokens.

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

## Certificate filters

`CertFilters` narrows the entries a key store lists to the ones worth offering for signing. It has four switches:

| Field | Default | Effect |
| --- | --- | --- |
| `show_expired` | off | Off hides certificates outside their validity period, whether expired or not yet valid. |
| `only_signature` | off | On keeps only certificates whose key usage includes `nonRepudiation`. A certificate without a key usage extension does not qualify. |
| `only_alias` | off | On keeps only pseudonym certificates, those whose subject has the `pseudonym` attribute. |
| `skip_dnie_auth` | on | On drops a DNIe authentication certificate: one issued by "AC DNIE ..." (OU `DNIE`, O `DIRECCION GENERAL DE LA POLICIA`, C `ES`) with the `digitalSignature` key usage. |

The filters combine with AND. `CertFilters::apply` takes a `Clock`, so validity is judged at a time the caller controls. Filters decide what is offered; they do not stop a caller from signing with an alias it names explicitly.

## macOS Keychain

`KeychainKeyStore::open()` lists the signing identities (a certificate together with its private key) in the user's keychain search list; `open_in(path)` restricts it to one keychain file. Signing goes through the Keychain (`SecKeyCreateSignature`), so the private key never leaves it: RSA signs PKCS#1 v1.5 with SHA-256, SHA-384 or SHA-512, and ECDSA signs X9.62 with the same digests, returned as DER.

macOS itself decides whether a key may be used and shows its own prompt (the login password or Touch ID). This backend asks the `AuthPrompt` for nothing and sees no secret; if the user declines, the error is `KeystoreError::AccessDenied`. The alias of an entry is the certificate's subject summary, made unique with a `#n` suffix when two share it. The chain is built from the other certificates in the same keychains, and from the system's own chain building when none is found.

The implementation is compiled on macOS only. On other systems `KeychainKeyStore` exists, and `open()` fails with an error saying the Keychain is available only on macOS. The tests that use a real keychain build a throwaway keychain file and run only on macOS; they have to be run on a Mac (or the macOS CI job) because they cannot run anywhere else.
