//! PKCS#11 tokens (smart cards, HSMs, the Spanish DNIe through OpenSC) as a key store.
//!
//! Certificates are public objects, so listing needs no PIN. The private key never leaves the
//! token: [`KeyStore::sign`] logs in with the user PIN, has the token sign, and logs out again.
//! Keys and certificates are paired by `CKA_ID`.
//!
//! One `Pkcs11` library handle is kept per module path for the life of the process. PKCS#11
//! modules are initialized once per process and finalized when the last handle goes away, so
//! opening the same module twice must share a handle.

use crate::{AuthPrompt, AuthRequest, Entry, KeyStore, SecretKind};
use certsign_core::{DigestAlg, Error, KeyType, KeystoreError, Result, SigAlg};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::{Error as CkError, RvError},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, CertificateType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
};
use der::Decode;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};
use x509_cert::{Certificate, ext::pkix::BasicConstraints};

fn backend(msg: impl Into<String>) -> Error {
    KeystoreError::Backend(msg.into()).into()
}

fn ck(context: &str, e: CkError) -> Error {
    backend(format!("PKCS#11 {context}: {e}"))
}

/// Where the OpenSC module usually is, for each operating system, best guess first.
pub fn default_module_candidates() -> Vec<PathBuf> {
    let paths: &[&str] = if cfg!(target_os = "windows") {
        &[
            r"C:\Windows\System32\opensc-pkcs11.dll",
            r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
            r"C:\Program Files (x86)\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
        ]
    } else if cfg!(target_os = "macos") {
        &[
            "/Library/OpenSC/lib/opensc-pkcs11.so",
            "/opt/homebrew/lib/opensc-pkcs11.so",
            "/usr/local/lib/opensc-pkcs11.so",
        ]
    } else {
        &[
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
            "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
            "/usr/lib64/opensc-pkcs11.so",
            "/usr/lib/opensc-pkcs11.so",
            "/usr/lib/pkcs11/opensc-pkcs11.so",
            "/usr/local/lib/opensc-pkcs11.so",
        ]
    };
    paths.iter().map(PathBuf::from).collect()
}

/// The first default OpenSC module that exists on this machine.
pub fn detect_default_module() -> Option<PathBuf> {
    default_module_candidates().into_iter().find(|p| p.exists())
}

fn load_module(path: &Path) -> Result<Arc<Pkcs11>> {
    static MODULES: OnceLock<Mutex<HashMap<PathBuf, Arc<Pkcs11>>>> = OnceLock::new();
    let mut modules = MODULES
        .get_or_init(Default::default)
        .lock()
        .expect("module registry");
    if let Some(m) = modules.get(path) {
        return Ok(Arc::clone(m));
    }
    let ctx = Pkcs11::new(path).map_err(|e| {
        backend(format!(
            "cannot load PKCS#11 module {}: {e}",
            path.display()
        ))
    })?;
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => return Err(ck("initialization", e)),
    }
    let ctx = Arc::new(ctx);
    modules.insert(path.to_owned(), Arc::clone(&ctx));
    Ok(ctx)
}

/// One certificate on the token, with what is needed to find its key.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TokenCert {
    id: Vec<u8>,
    label: String,
    der: Vec<u8>,
}

struct TokenEntry {
    entry: Entry,
    id: Vec<u8>,
    key_type: KeyType,
}

/// A PKCS#11 token.
pub struct Pkcs11KeyStore {
    ctx: Arc<Pkcs11>,
    slot: Slot,
    label: String,
    entries: Vec<TokenEntry>,
}

impl std::fmt::Debug for Pkcs11KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let aliases: Vec<&str> = self
            .entries
            .iter()
            .map(|e| e.entry.alias.as_str())
            .collect();
        f.debug_struct("Pkcs11KeyStore")
            .field("token", &self.label)
            .field("aliases", &aliases)
            .finish_non_exhaustive()
    }
}

impl Pkcs11KeyStore {
    /// Opens the token in `slot` of the PKCS#11 `module`.
    ///
    /// An empty `module` path means the OpenSC module in its default place for this system.
    /// With no `slot`, the only token present is used; several tokens need an explicit slot.
    pub fn open(module: impl AsRef<Path>, slot: Option<u64>) -> Result<Self> {
        let module = module.as_ref();
        let module = if module.as_os_str().is_empty() {
            detect_default_module().ok_or_else(|| {
                backend(format!(
                    "no PKCS#11 module given and OpenSC was not found; looked in: {}",
                    default_module_candidates()
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?
        } else {
            module.to_owned()
        };
        let ctx = load_module(&module)?;

        let slots = ctx
            .get_slots_with_token()
            .map_err(|e| ck("listing slots", e))?;
        let chosen = match slot {
            Some(id) => slots
                .iter()
                .copied()
                .find(|s| s.id() == id)
                .ok_or_else(|| backend(format!("slot {id} has no token")))?,
            None => match slots.as_slice() {
                [] => return Err(backend("no token is present")),
                [only] => *only,
                several => {
                    let mut described = Vec::new();
                    for s in several {
                        let label = ctx
                            .get_token_info(*s)
                            .map(|i| i.label().to_owned())
                            .unwrap_or_default();
                        described.push(format!("{} ({label})", s.id()));
                    }
                    return Err(backend(format!(
                        "several tokens are present, choose one with a slot: {}",
                        described.join(", ")
                    )));
                }
            },
        };
        let label = ctx
            .get_token_info(chosen)
            .map_err(|e| ck("reading token info", e))?
            .label()
            .to_owned();

        let session = ctx
            .open_ro_session(chosen)
            .map_err(|e| ck("opening a session", e))?;
        let certs = read_certificates(&session)?;
        let key_ids = visible_private_key_ids(&session)?;
        let entries = select_entries(&certs, &key_ids)?;
        Ok(Self {
            ctx,
            slot: chosen,
            label,
            entries,
        })
    }

    /// The token's label.
    pub fn token_label(&self) -> &str {
        &self.label
    }
}

fn read_certificates(session: &Session) -> Result<Vec<TokenCert>> {
    let handles = session
        .find_objects(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
        ])
        .map_err(|e| ck("finding certificates", e))?;
    let mut certs = Vec::new();
    for handle in handles {
        let attrs = session
            .get_attributes(
                handle,
                &[
                    AttributeType::Id,
                    AttributeType::Label,
                    AttributeType::Value,
                ],
            )
            .map_err(|e| ck("reading a certificate", e))?;
        let (mut id, mut label, mut der) = (Vec::new(), String::new(), Vec::new());
        for a in attrs {
            match a {
                Attribute::Id(v) => id = v,
                Attribute::Label(v) => label = String::from_utf8_lossy(&v).trim().to_owned(),
                Attribute::Value(v) => der = v,
                _ => {}
            }
        }
        if !der.is_empty() {
            certs.push(TokenCert { id, label, der });
        }
    }
    Ok(certs)
}

/// `CKA_ID`s of the private keys the token shows without a login. Many tokens show none until
/// the user logs in, so an empty result means "unknown", not "no keys".
fn visible_private_key_ids(session: &Session) -> Result<Vec<Vec<u8>>> {
    let handles = session
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])
        .map_err(|e| ck("finding keys", e))?;
    let mut ids = Vec::new();
    for h in handles {
        for a in session
            .get_attributes(h, &[AttributeType::Id])
            .map_err(|e| ck("reading a key", e))?
        {
            if let Attribute::Id(id) = a {
                ids.push(id);
            }
        }
    }
    Ok(ids)
}

fn is_ca(cert: &Certificate) -> bool {
    cert.tbs_certificate()
        .get_extension::<BasicConstraints>()
        .ok()
        .flatten()
        .is_some_and(|(_, bc)| bc.ca)
}

/// Public key kind of a certificate: RSA, or ECDSA on a curve we can sign with.
fn key_type_of(cert: &Certificate) -> Option<KeyType> {
    const RSA: &str = "1.2.840.113549.1.1.1";
    const EC: &str = "1.2.840.10045.2.1";
    match cert
        .tbs_certificate()
        .subject_public_key_info()
        .algorithm
        .oid
        .to_string()
        .as_str()
    {
        RSA => Some(KeyType::Rsa),
        EC => Some(KeyType::Ecdsa),
        _ => None,
    }
}

/// Decides which certificates are signing identities and builds their chains.
///
/// When the token shows private keys, a certificate counts if a key has its `CKA_ID`. When it
/// shows none (keys are hidden until login), every certificate that is not a CA counts.
fn select_entries(certs: &[TokenCert], visible_key_ids: &[Vec<u8>]) -> Result<Vec<TokenEntry>> {
    let parsed: Vec<(&TokenCert, Certificate)> = certs
        .iter()
        .filter_map(|c| Certificate::from_der(&c.der).ok().map(|p| (c, p)))
        .collect();

    let mut entries: Vec<TokenEntry> = Vec::new();
    for (cert, parsed_cert) in &parsed {
        let wanted = if visible_key_ids.is_empty() {
            !is_ca(parsed_cert)
        } else {
            visible_key_ids.contains(&cert.id)
        };
        let Some(key_type) = key_type_of(parsed_cert).filter(|_| wanted) else {
            continue;
        };

        // Follow issuers through the other certificates on the token.
        let mut chain = vec![cert.der.clone()];
        let mut current = parsed_cert;
        for _ in 0..parsed.len() {
            let issuer = current.tbs_certificate().issuer();
            if issuer == current.tbs_certificate().subject() {
                break;
            }
            let Some((next, next_parsed)) = parsed
                .iter()
                .find(|(c, p)| p.tbs_certificate().subject() == issuer && !chain.contains(&c.der))
            else {
                break;
            };
            chain.push(next.der.clone());
            current = next_parsed;
        }

        let base = if cert.label.is_empty() {
            format!("id:{}", hex(&cert.id))
        } else {
            cert.label.clone()
        };
        let alias = if entries.iter().any(|e| e.entry.alias == base) {
            format!("{base}#{}", hex(&cert.id))
        } else {
            base
        };
        if let Some(entry) = Entry::new(alias, chain) {
            entries.push(TokenEntry {
                entry,
                id: cert.id.clone(),
                key_type,
            });
        }
    }
    Ok(entries)
}

/// What a failed login reports. PKCS#11 has no retry counter, only the token's `FINAL_TRY` flag:
/// when it is set, exactly one try is left.
fn bad_pin(final_try: bool) -> KeystoreError {
    KeystoreError::BadPin {
        retries_left: final_try.then_some(1),
    }
}

fn locked(token: &str) -> Error {
    backend(format!("the PIN of token {token} is locked"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash(d: DigestAlg, data: &[u8]) -> Vec<u8> {
    match d {
        DigestAlg::Sha256 => Sha256::digest(data).to_vec(),
        DigestAlg::Sha384 => Sha384::digest(data).to_vec(),
        DigestAlg::Sha512 => Sha512::digest(data).to_vec(),
    }
}

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

/// Encodes a token's raw ECDSA signature (`r || s`, each as wide as the curve) as the DER
/// `ECDSA-Sig-Value` that CMS carries.
pub fn ecdsa_raw_to_der(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(backend(format!(
            "an ECDSA signature of {} bytes cannot be split into r and s",
            raw.len()
        )));
    }
    let (r, s) = raw.split_at(raw.len() / 2);
    // A DER INTEGER is minimal and positive: drop leading zeros, add one if the top bit is set.
    let integer = |bytes: &[u8]| -> Vec<u8> {
        let trimmed = match bytes.iter().position(|b| *b != 0) {
            Some(i) => &bytes[i..],
            None => &[0],
        };
        let mut out = vec![0x02];
        let pad = trimmed[0] & 0x80 != 0;
        push_len(&mut out, trimmed.len() + usize::from(pad));
        if pad {
            out.push(0);
        }
        out.extend_from_slice(trimmed);
        out
    };
    let mut body = integer(r);
    body.extend(integer(s));
    let mut out = vec![0x30];
    push_len(&mut out, body.len());
    out.extend(body);
    Ok(out)
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
}

impl Pkcs11KeyStore {
    fn find_key(&self, session: &Session, entry: &TokenEntry) -> Result<ObjectHandle> {
        session
            .find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Id(entry.id.clone()),
            ])
            .map_err(|e| ck("finding the private key", e))?
            .into_iter()
            .next()
            .ok_or_else(|| {
                backend(format!(
                    "the token has no private key with CKA_ID {}",
                    hex(&entry.id)
                ))
            })
    }

    /// Logs in with the user PIN, asking `auth` for it. Does nothing if the token needs no login.
    fn login(&self, session: &Session, auth: &dyn AuthPrompt) -> Result<()> {
        let info = self
            .ctx
            .get_token_info(self.slot)
            .map_err(|e| ck("reading token info", e))?;
        if !info.login_required() {
            return Ok(());
        }
        if info.user_pin_locked() {
            return Err(locked(&self.label));
        }
        if info.protected_authentication_path() {
            // A reader with its own keypad: the PIN is typed on the device, not given to us.
            return match session.login(UserType::User, None) {
                Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
                Err(e) => Err(self.login_error(e)),
            };
        }
        let request = AuthRequest {
            kind: SecretKind::Pin,
            target: &self.label,
            retries_left: info.user_pin_final_try().then_some(1),
        };
        let pin = auth.secret(&request)?;
        match session.login(UserType::User, Some(&pin)) {
            Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
            Err(e) => Err(self.login_error(e)),
        }
    }

    fn login_error(&self, e: CkError) -> Error {
        match e {
            CkError::Pkcs11(RvError::PinIncorrect | RvError::PinLenRange, _) => {
                let final_try = self
                    .ctx
                    .get_token_info(self.slot)
                    .map(|i| i.user_pin_final_try())
                    .unwrap_or(false);
                bad_pin(final_try).into()
            }
            CkError::Pkcs11(RvError::PinLocked, _) => locked(&self.label),
            other => ck("login", other),
        }
    }
}

impl KeyStore for Pkcs11KeyStore {
    fn entries(&self) -> Result<Vec<Entry>> {
        Ok(self.entries.iter().map(|e| e.entry.clone()).collect())
    }

    fn sign(&self, alias: &str, alg: SigAlg, tbs: &[u8], auth: &dyn AuthPrompt) -> Result<Vec<u8>> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.entry.alias == alias)
            .ok_or_else(|| Error::from(KeystoreError::UnknownAlias(alias.to_owned())))?;
        if entry.key_type != alg.key {
            return Err(Error::UnsupportedAlgorithm(format!(
                "{alg} cannot be used with the {:?} key {alias:?}",
                entry.key_type
            )));
        }
        let digest = hash(alg.digest, tbs);

        let session = self
            .ctx
            .open_ro_session(self.slot)
            .map_err(|e| ck("opening a session", e))?;
        self.login(&session, auth)?;
        let result = (|| {
            let key = self.find_key(&session, entry)?;
            match alg.key {
                KeyType::Rsa => {
                    let mut input = pkcs1_prefix(alg.digest);
                    input.extend_from_slice(&digest);
                    session
                        .sign(&Mechanism::RsaPkcs, key, &input)
                        .map_err(|e| ck("signing", e))
                }
                KeyType::Ecdsa => {
                    // The token reduces the hash to the curve's size; hand it exactly that many bytes.
                    let field = field_size(&entry.entry)?;
                    let input = &digest[..digest.len().min(field)];
                    let raw = session
                        .sign(&Mechanism::Ecdsa, key, input)
                        .map_err(|e| ck("signing", e))?;
                    ecdsa_raw_to_der(&raw)
                }
            }
        })();
        // Do not leave the token unlocked for whatever runs next.
        let _ = session.logout();
        result
    }
}

/// Bytes in a coordinate of the entry's EC curve: 32 for P-256, 48 for P-384.
fn field_size(entry: &Entry) -> Result<usize> {
    const P256: &str = "1.2.840.10045.3.1.7";
    const P384: &str = "1.3.132.0.34";
    let cert = Certificate::from_der(entry.certificate())
        .map_err(|e| backend(format!("unreadable certificate: {e}")))?;
    let curve = cert
        .tbs_certificate()
        .subject_public_key_info()
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
        .map(|o| o.to_string());
    match curve.as_deref() {
        Some(P256) => Ok(32),
        Some(P384) => Ok(48),
        other => Err(Error::UnsupportedAlgorithm(format!(
            "elliptic curve {}",
            other.unwrap_or("(unnamed)")
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_ecdsa_becomes_der() {
        // Both halves have the top bit set: each INTEGER gets a leading zero.
        let raw: Vec<u8> = [vec![0x80; 32], vec![0xFF; 32]].concat();
        let der = ecdsa_raw_to_der(&raw).unwrap();
        assert_eq!(der[0], 0x30);
        assert_eq!(der[1] as usize, der.len() - 2);
        assert_eq!(&der[2..5], &[0x02, 0x21, 0x00]);
        assert_eq!(der[5], 0x80);
        assert_eq!(&der[2 + 35..2 + 38], &[0x02, 0x21, 0x00]);
    }

    #[test]
    fn leading_zeros_are_dropped() {
        let mut raw = vec![0u8; 64];
        raw[31] = 0x05; // r = 5
        raw[63] = 0x7F; // s = 127
        assert_eq!(
            ecdsa_raw_to_der(&raw).unwrap(),
            [0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x7F]
        );
        // Zero is a single zero byte.
        assert_eq!(
            ecdsa_raw_to_der(&[0, 0]).unwrap(),
            [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]
        );
    }

    #[test]
    fn odd_or_empty_signatures_are_errors() {
        assert!(ecdsa_raw_to_der(&[]).is_err());
        assert!(ecdsa_raw_to_der(&[1, 2, 3]).is_err());
    }

    #[test]
    fn long_form_lengths() {
        // P-384 halves of 48 bytes with the top bit set make a 101-byte body: still short form;
        // 66-byte halves (P-521) need the one-byte long form for the outer SEQUENCE.
        let raw: Vec<u8> = [vec![0xAA; 66], vec![0xBB; 66]].concat();
        let der = ecdsa_raw_to_der(&raw).unwrap();
        assert_eq!(&der[..2], &[0x30, 0x81]);
        assert_eq!(der[2] as usize, der.len() - 3);
    }

    #[test]
    fn a_failed_pin_reports_the_final_try_flag() {
        assert_eq!(bad_pin(false), KeystoreError::BadPin { retries_left: None });
        assert_eq!(
            bad_pin(true),
            KeystoreError::BadPin {
                retries_left: Some(1)
            }
        );
        assert_eq!(bad_pin(true).to_string(), "wrong PIN (1 try left)");
    }

    #[test]
    fn a_locked_pin_names_the_token() {
        assert_eq!(
            locked("DNIe").to_string(),
            "key store: the PIN of token DNIe is locked"
        );
    }
}
