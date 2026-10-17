# certsign-keystore

Access to signing keys and certificate chains through a `KeyStore` trait, without ever handing the private key to the caller. Backends: PKCS#12 files and PKCS#11 tokens.

## Traits

- `KeyStore` lists `Entry` values (an alias and a certificate chain, end-entity first) and signs data with the key of an alias. The store does the private-key operation itself and returns only the signature: PKCS#1 v1.5 for RSA, a DER `ECDSA-Sig-Value` for ECDSA.
- `AuthPrompt` is where a store gets the secret it needs: a file's password when it is opened, a token's PIN when something is signed (and not before). A terminal, an environment variable or a dialog can implement it. `StaticPrompt` and `NoPrompt` cover tests and callers that already hold, or refuse to supply, a secret.

## Secrets

Secrets cross the API as `SecretString`: wiped from memory when dropped and absent from `Debug` output. Backends that need a secret in another encoding (PKCS#12 derives its keys from a null-terminated UTF-16 big-endian password) hold it in `SecretBytes`, which is wiped on drop or on demand. Key store failures, wrong passwords and PINs included, are `KeystoreError` values, so a caller can tell a bad PIN (with the retries left, when the token says) from a missing secret.
