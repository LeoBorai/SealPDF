//! The macOS Keychain as a key store.
//!
//! Identities (a certificate together with its private key) are listed from the user's keychains
//! and signing goes through `SecKeyCreateSignature`, so the private key never leaves the Keychain.
//! macOS decides whether the key may be used and shows its own prompt (the login password or
//! Touch ID). This module asks for no secret.
//!
//! The real implementation is compiled on macOS only. On every other system [`KeychainKeyStore`]
//! exists but [`KeychainKeyStore::open`] fails with an error that says so.

use crate::{AuthPrompt, Entry, KeyStore};
use sealpdf_core::{Error, KeystoreError, Result, SigAlg};

#[cfg(target_os = "macos")]
use sealpdf_core::{DigestAlg, KeyType};
#[cfg(target_os = "macos")]
use security_framework::{
    certificate::SecCertificate,
    identity::SecIdentity,
    item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult},
    key::Algorithm,
    policy::SecPolicy,
    trust::SecTrust,
};

fn backend(msg: impl Into<String>) -> Error {
    KeystoreError::Backend(msg.into()).into()
}

/// The signing identities of the user's keychains.
pub struct KeychainKeyStore {
    #[cfg(target_os = "macos")]
    entries: Vec<KeychainEntry>,
}

#[cfg(target_os = "macos")]
struct KeychainEntry {
    entry: Entry,
    identity: SecIdentity,
    key_type: KeyType,
}

impl std::fmt::Debug for KeychainKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(target_os = "macos")]
        {
            let aliases: Vec<&str> = self
                .entries
                .iter()
                .map(|e| e.entry.alias.as_str())
                .collect();
            f.debug_struct("KeychainKeyStore")
                .field("aliases", &aliases)
                .finish_non_exhaustive()
        }
        #[cfg(not(target_os = "macos"))]
        f.debug_struct("KeychainKeyStore").finish_non_exhaustive()
    }
}

#[cfg(not(target_os = "macos"))]
impl KeychainKeyStore {
    /// Always fails: the Keychain exists only on macOS.
    pub fn open() -> Result<Self> {
        Err(backend("the macOS Keychain is available only on macOS"))
    }

    /// Always fails: the Keychain exists only on macOS.
    pub fn open_in(_path: &std::path::Path) -> Result<Self> {
        Self::open()
    }
}

#[cfg(not(target_os = "macos"))]
impl KeyStore for KeychainKeyStore {
    fn entries(&self) -> Result<Vec<Entry>> {
        Err(backend("the macOS Keychain is available only on macOS"))
    }

    fn sign(
        &self,
        _alias: &str,
        _alg: SigAlg,
        _tbs: &[u8],
        _auth: &dyn AuthPrompt,
    ) -> Result<Vec<u8>> {
        Err(backend("the macOS Keychain is available only on macOS"))
    }
}

/// `errSecItemNotFound`: nothing matched the search.
#[cfg(target_os = "macos")]
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
/// `errSecUserCanceled`, `errSecAuthFailed` and `errSecInteractionNotAllowed`: the user or the
/// system said no to using a key.
#[cfg(target_os = "macos")]
const ACCESS_DENIED_CODES: [i64; 3] = [-128, -25293, -25308];

#[cfg(target_os = "macos")]
impl KeychainKeyStore {
    /// Opens the keychains in the user's search list (the login keychain and the others it names).
    pub fn open() -> Result<Self> {
        Self::from_keychains(None)
    }

    /// Opens only the keychain file at `path`.
    pub fn open_in(path: &std::path::Path) -> Result<Self> {
        use security_framework::os::macos::keychain::SecKeychain;
        // The Security framework hands out a handle for a path that does not exist and only fails
        // later, on first use, so a missing file has to be rejected here.
        if !path.is_file() {
            return Err(backend(format!(
                "cannot open the keychain {}: no such file",
                path.display()
            )));
        }
        let keychain = SecKeychain::open(path)
            .map_err(|e| backend(format!("cannot open the keychain {}: {e}", path.display())))?;
        Self::from_keychains(Some(vec![keychain]))
    }

    /// Runs a search for items of `class` in `keychains` (or the search list) and returns the references.
    fn search(
        class: ItemClass,
        keychains: &Option<Vec<security_framework::os::macos::keychain::SecKeychain>>,
    ) -> Result<Vec<Reference>> {
        let mut options = ItemSearchOptions::new();
        options.class(class).load_refs(true).limit(Limit::All);
        if let Some(k) = keychains {
            options.keychains(k);
        }
        match options.search() {
            Ok(found) => Ok(found
                .into_iter()
                .filter_map(|r| match r {
                    SearchResult::Ref(reference) => Some(reference),
                    _ => None,
                })
                .collect()),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(Vec::new()),
            Err(e) => Err(backend(format!("cannot read the keychain: {e}"))),
        }
    }

    fn from_keychains(
        keychains: Option<Vec<security_framework::os::macos::keychain::SecKeychain>>,
    ) -> Result<Self> {
        // Every certificate in the same keychains, to build chains from.
        let known: Vec<Vec<u8>> = Self::search(ItemClass::certificate(), &keychains)?
            .into_iter()
            .filter_map(|r| match r {
                Reference::Certificate(c) => Some(c.to_der()),
                _ => None,
            })
            .collect();

        let mut entries = Vec::new();
        for reference in Self::search(ItemClass::identity(), &keychains)? {
            let Reference::Identity(identity) = reference else {
                continue;
            };
            let Ok(certificate) = identity.certificate() else {
                continue;
            };
            let der = certificate.to_der();
            let Some(key_type) = key_type_of(&der) else {
                continue;
            };
            let mut chain = chain_from(&der, &known);
            if chain.len() == 1 {
                // No issuer among the keychain's certificates: let the system try.
                chain = system_chain(&certificate).unwrap_or(chain);
            }
            let label = certificate.subject_summary();
            let alias = if label.is_empty() {
                "certificate".to_owned()
            } else {
                label
            };
            if let Some(entry) = Entry::new(alias, chain) {
                entries.push(KeychainEntry {
                    entry,
                    identity,
                    key_type,
                });
            }
        }

        // The search order is not defined: sort, then keep aliases unique.
        entries.sort_by(|a, b| {
            a.entry
                .alias
                .cmp(&b.entry.alias)
                .then_with(|| a.entry.certificate().cmp(b.entry.certificate()))
        });
        let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for e in &mut entries {
            let count = seen.entry(e.entry.alias.clone()).or_insert(0);
            *count += 1;
            if *count > 1 {
                let alias = format!("{} #{}", e.entry.alias, count);
                if let Some(renamed) = Entry::new(alias, e.entry.chain().to_vec()) {
                    e.entry = renamed;
                }
            }
        }
        Ok(Self { entries })
    }
}

/// `leaf` followed by its issuers found among `known`, up to a self-signed certificate.
#[cfg(target_os = "macos")]
fn chain_from(leaf: &[u8], known: &[Vec<u8>]) -> Vec<Vec<u8>> {
    use der::Decode;
    use x509_cert::Certificate;
    let parsed: Vec<(&Vec<u8>, Certificate)> = known
        .iter()
        .filter_map(|der| Certificate::from_der(der).ok().map(|c| (der, c)))
        .collect();
    let mut chain = vec![leaf.to_vec()];
    let Ok(mut current) = Certificate::from_der(leaf) else {
        return chain;
    };
    for _ in 0..parsed.len() {
        let issuer = current.tbs_certificate().issuer().clone();
        if &issuer == current.tbs_certificate().subject() {
            break;
        }
        let Some((der, next)) = parsed
            .iter()
            .find(|(d, c)| c.tbs_certificate().subject() == &issuer && !chain.contains(d))
        else {
            break;
        };
        chain.push((*der).clone());
        current = next.clone();
    }
    chain
}

/// The chain the system builds for `certificate`, signing certificate first.
#[cfg(target_os = "macos")]
fn system_chain(certificate: &SecCertificate) -> Option<Vec<Vec<u8>>> {
    let trust = SecTrust::create_with_certificates(
        std::slice::from_ref(certificate),
        &[SecPolicy::create_x509()],
    )
    .ok()?;
    // Evaluating builds the chain. Whether it is trusted does not matter here: an untrusted root
    // still belongs in the signature, and the verifier decides what to trust.
    let _ = trust.evaluate_with_error();
    let chain: Vec<Vec<u8>> = trust.chain().iter().map(|c| c.to_der()).collect();
    (chain.first() == Some(&certificate.to_der())).then_some(chain)
}

/// RSA or EC, from the certificate's public key.
#[cfg(target_os = "macos")]
fn key_type_of(cert_der: &[u8]) -> Option<KeyType> {
    use der::Decode;
    let cert = x509_cert::Certificate::from_der(cert_der).ok()?;
    match cert
        .tbs_certificate()
        .subject_public_key_info()
        .algorithm
        .oid
        .to_string()
        .as_str()
    {
        "1.2.840.113549.1.1.1" => Some(KeyType::Rsa),
        "1.2.840.10045.2.1" => Some(KeyType::Ecdsa),
        _ => None,
    }
}

/// The Keychain algorithm that hashes the data and signs it with PKCS#1 v1.5 (RSA) or as X9.62 DER (ECDSA).
#[cfg(target_os = "macos")]
fn algorithm(alg: SigAlg) -> Algorithm {
    match (alg.key, alg.digest) {
        (KeyType::Rsa, DigestAlg::Sha256) => Algorithm::RSASignatureMessagePKCS1v15SHA256,
        (KeyType::Rsa, DigestAlg::Sha384) => Algorithm::RSASignatureMessagePKCS1v15SHA384,
        (KeyType::Rsa, DigestAlg::Sha512) => Algorithm::RSASignatureMessagePKCS1v15SHA512,
        (KeyType::Ecdsa, DigestAlg::Sha256) => Algorithm::ECDSASignatureMessageX962SHA256,
        (KeyType::Ecdsa, DigestAlg::Sha384) => Algorithm::ECDSASignatureMessageX962SHA384,
        (KeyType::Ecdsa, DigestAlg::Sha512) => Algorithm::ECDSASignatureMessageX962SHA512,
    }
}

#[cfg(target_os = "macos")]
impl KeyStore for KeychainKeyStore {
    fn entries(&self) -> Result<Vec<Entry>> {
        Ok(self.entries.iter().map(|e| e.entry.clone()).collect())
    }

    /// Signs through the Keychain. macOS may show its own prompt; `auth` is not used.
    fn sign(
        &self,
        alias: &str,
        alg: SigAlg,
        tbs: &[u8],
        _auth: &dyn AuthPrompt,
    ) -> Result<Vec<u8>> {
        let found = self
            .entries
            .iter()
            .find(|e| e.entry.alias == alias)
            .ok_or_else(|| Error::from(KeystoreError::UnknownAlias(alias.to_owned())))?;
        if found.key_type != alg.key {
            return Err(Error::UnsupportedAlgorithm(format!(
                "{alg} cannot be used with the {:?} key {alias:?}",
                found.key_type
            )));
        }
        let key = found.identity.private_key().map_err(|e| {
            backend(format!(
                "the identity {alias:?} has no usable private key: {e}"
            ))
        })?;
        key.create_signature(algorithm(alg), tbs).map_err(|e| {
            if ACCESS_DENIED_CODES.contains(&(e.code() as i64)) {
                KeystoreError::AccessDenied(e.description().to_string()).into()
            } else {
                backend(format!("the Keychain could not sign: {}", e.description()))
            }
        })
    }
}
