//! PKCS#12 (`.p12` / `.pfx`) files as a key store.
//!
//! Parsing and decryption are done by `p12-keystore`, which yields each entry's certificate chain
//! and its private key as PKCS#8. This module wraps that in a [`KeyStore`]: it maps a failed MAC
//! to a bad password, keeps the keys in zeroizing buffers, and signs with `rsa` or `p256`/`p384`
//! after reading the key's algorithm from the PKCS#8 header.
//!
//! `p12-keystore` is pinned to the 0.2 series. Later versions depend on pre-release RustCrypto
//! crates (`pkcs12` 0.2 pre-releases with an exact `cms` version) that cannot be built together
//! with the `cms` release candidate the CMS crate uses. Revisit when `cms` 0.3 is final.
//!
//! The PKCS#8 copy of each key is held in a [`Zeroizing`] buffer, but `p12-keystore` makes its own
//! copy while parsing, which this module cannot wipe.

use crate::{AuthPrompt, AuthRequest, Entry, KeyStore, SecretKind};
use der::{Decode, Reader, SliceReader, asn1::ObjectIdentifier};
use p12_keystore::{KeyStore as P12, KeyStoreEntry};
use p256::{ecdsa::signature::hazmat::PrehashSigner, pkcs8::DecodePrivateKey as _};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, pkcs8::DecodePrivateKey as _};
use sealpdf_core::{DigestAlg, Error, KeyType, KeystoreError, Result, SigAlg};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifierOwned as AlgId;
use std::path::Path;
use zeroize::Zeroizing;

/// The signing identities of a PKCS#12 file.
///
/// The file is opened, decrypted and checked once, with the password the [`AuthPrompt`] gives.
/// A wrong password fails the whole open: no entries are listed. Private keys stay inside this
/// value and are used only by [`KeyStore::sign`].
pub struct Pkcs12KeyStore {
    entries: Vec<(Entry, Zeroizing<Vec<u8>>)>,
}

const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

fn backend(msg: impl Into<String>) -> Error {
    KeystoreError::Backend(msg.into()).into()
}

impl Pkcs12KeyStore {
    /// Opens the file at `path`.
    pub fn open(path: impl AsRef<Path>, auth: &dyn AuthPrompt) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)
            .map_err(|e| backend(format!("cannot read {}: {e}", path.display())))?;
        Self::from_bytes(&bytes, &path.display().to_string(), auth)
    }

    /// Opens PKCS#12 data. `target` names it in password prompts.
    pub fn from_bytes(data: &[u8], target: &str, auth: &dyn AuthPrompt) -> Result<Self> {
        let password = auth.secret(&AuthRequest::new(SecretKind::Password, target))?;
        let store = P12::from_pkcs12(data, password.expose_secret()).map_err(|e| match e {
            // The MAC covers the whole file, so a wrong password fails it first. Files without a
            // MAC fail while unpadding the first decrypted block.
            p12_keystore::error::Error::MacError(_) | p12_keystore::error::Error::UnpadError => {
                Error::from(KeystoreError::BadPassword)
            }
            other => backend(format!("{target} is not a usable PKCS#12 file: {other}")),
        })?;

        let mut entries = Vec::new();
        for (alias, entry) in store.entries() {
            let KeyStoreEntry::PrivateKeyChain(chain) = entry else {
                continue;
            };
            let der: Vec<Vec<u8>> = chain.chain().iter().map(|c| c.as_der().to_vec()).collect();
            let Some(entry) = Entry::new(alias.clone(), der) else {
                continue;
            };
            entries.push((entry, Zeroizing::new(chain.key().to_vec())));
        }
        Ok(Self { entries })
    }
}

impl std::fmt::Debug for Pkcs12KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let aliases: Vec<&str> = self.entries.iter().map(|(e, _)| e.alias.as_str()).collect();
        f.debug_struct("Pkcs12KeyStore")
            .field("aliases", &aliases)
            .finish_non_exhaustive()
    }
}

/// The `AlgorithmIdentifier` of a PKCS#8 `PrivateKeyInfo`, which says what kind of key it holds.
/// The remaining fields (the key itself, attributes, public key) are left to the key decoders.
fn pkcs8_algorithm(pkcs8: &[u8]) -> der::Result<AlgId> {
    let mut reader = SliceReader::new(pkcs8)?;
    reader.sequence(|r| {
        let _version = u8::decode(r)?;
        let algorithm = AlgId::decode(r)?;
        // Skip what follows so the sequence counts as fully read.
        let rest = r.remaining_len();
        r.read_slice(rest)?;
        Ok(algorithm)
    })
}

fn hash(d: DigestAlg, data: &[u8]) -> Vec<u8> {
    match d {
        DigestAlg::Sha256 => Sha256::digest(data).to_vec(),
        DigestAlg::Sha384 => Sha384::digest(data).to_vec(),
        DigestAlg::Sha512 => Sha512::digest(data).to_vec(),
    }
}

/// DER `DigestInfo` header that precedes the hash in a PKCS#1 v1.5 signature.
fn pkcs1_prefix(d: DigestAlg) -> Vec<u8> {
    let (last, len) = match d {
        DigestAlg::Sha256 => (0x01, 0x20),
        DigestAlg::Sha384 => (0x02, 0x30),
        DigestAlg::Sha512 => (0x03, 0x40),
    };
    let mut p = vec![
        0x30,
        0x11 + len,
        0x30,
        0x0d,
        0x06,
        0x09,
        0x60,
        0x86,
        0x48,
        0x01,
        0x65,
        0x03,
        0x04,
        0x02,
    ];
    p.extend_from_slice(&[last, 0x05, 0x00, 0x04, len]);
    p
}

fn sign_with_key(pkcs8: &[u8], alg: SigAlg, tbs: &[u8]) -> Result<Vec<u8>> {
    let algorithm =
        pkcs8_algorithm(pkcs8).map_err(|e| backend(format!("unreadable private key: {e}")))?;
    let digest = hash(alg.digest, tbs);
    let mismatch =
        |have: &str| Error::UnsupportedAlgorithm(format!("{alg} cannot be used with a {have} key"));

    if algorithm.oid == RSA_ENCRYPTION {
        if alg.key != KeyType::Rsa {
            return Err(mismatch("RSA"));
        }
        let key = RsaPrivateKey::from_pkcs8_der(pkcs8)
            .map_err(|e| backend(format!("unreadable RSA key: {e}")))?;
        let scheme = Pkcs1v15Sign {
            hash_len: Some(digest.len()),
            prefix: pkcs1_prefix(alg.digest).into_boxed_slice(),
        };
        // Blinded with system randomness, so timing does not leak the key.
        return key
            .sign_with_rng(&mut rand_core::OsRng, scheme, &digest)
            .map_err(|e| backend(format!("RSA signing failed: {e}")));
    }

    if algorithm.oid == EC_PUBLIC_KEY {
        if alg.key != KeyType::Ecdsa {
            return Err(mismatch("EC"));
        }
        let curve: ObjectIdentifier = algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as().ok())
            .ok_or_else(|| backend("EC key without a named curve"))?;
        let bad = |e: &dyn std::fmt::Display| backend(format!("ECDSA signing failed: {e}"));
        if curve == P256 {
            let key = p256::ecdsa::SigningKey::from_pkcs8_der(pkcs8).map_err(|e| bad(&e))?;
            let sig: p256::ecdsa::Signature = key.sign_prehash(&digest).map_err(|e| bad(&e))?;
            return Ok(sig.to_der().as_bytes().to_vec());
        }
        if curve == P384 {
            let key = p384::ecdsa::SigningKey::from_pkcs8_der(pkcs8).map_err(|e| bad(&e))?;
            let sig: p384::ecdsa::Signature = key.sign_prehash(&digest).map_err(|e| bad(&e))?;
            return Ok(sig.to_der().as_bytes().to_vec());
        }
        return Err(Error::UnsupportedAlgorithm(format!(
            "elliptic curve {curve}"
        )));
    }

    Err(Error::UnsupportedAlgorithm(format!(
        "private key algorithm {}",
        algorithm.oid
    )))
}

impl KeyStore for Pkcs12KeyStore {
    fn entries(&self) -> Result<Vec<Entry>> {
        Ok(self.entries.iter().map(|(e, _)| e.clone()).collect())
    }

    /// The file is already unlocked, so `auth` is not used.
    fn sign(
        &self,
        alias: &str,
        alg: SigAlg,
        tbs: &[u8],
        _auth: &dyn AuthPrompt,
    ) -> Result<Vec<u8>> {
        let (_, key) = self
            .entries
            .iter()
            .find(|(e, _)| e.alias == alias)
            .ok_or_else(|| Error::from(KeystoreError::UnknownAlias(alias.to_owned())))?;
        sign_with_key(key, alg, tbs)
    }
}
