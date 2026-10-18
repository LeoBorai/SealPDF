use crate::AuthPrompt;
use sealpdf_core::{Result, SigAlg};

/// A signing identity in a key store: an alias, the certificate and its chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub alias: String,
    /// DER certificates from the end-entity certificate to the root. Never empty.
    chain: Vec<Vec<u8>>,
}

impl Entry {
    /// `chain` goes from the end-entity certificate to the root. Returns `None` for an empty chain.
    pub fn new(alias: impl Into<String>, chain: Vec<Vec<u8>>) -> Option<Self> {
        (!chain.is_empty()).then(|| Self {
            alias: alias.into(),
            chain,
        })
    }

    /// DER of the end-entity (signing) certificate.
    pub fn certificate(&self) -> &[u8] {
        &self.chain[0]
    }

    /// DER of every certificate the store holds for this entry, end-entity first.
    pub fn chain(&self) -> &[Vec<u8>] {
        &self.chain
    }
}

/// Access to signing keys that never leaves the key material in the caller's hands.
///
/// Implementations do the private-key operation themselves (in a PKCS#12 file's decrypted key,
/// or on a token) and return only the signature. `auth` is asked for a secret only when one is
/// needed: a file's password when it is opened, a token's PIN when something is signed.
pub trait KeyStore {
    /// The entries that have a private key.
    fn entries(&self) -> Result<Vec<Entry>>;

    /// Signs `tbs` with the key of `alias`.
    ///
    /// For RSA the result is a PKCS#1 v1.5 signature; for ECDSA it is a DER `ECDSA-Sig-Value`,
    /// which is what a CMS `SignerInfo` carries. `tbs` is the data to be signed (the DER signed
    /// attributes), not its digest: the store hashes it with the digest of `alg`.
    fn sign(&self, alias: &str, alg: SigAlg, tbs: &[u8], auth: &dyn AuthPrompt) -> Result<Vec<u8>>;
}
