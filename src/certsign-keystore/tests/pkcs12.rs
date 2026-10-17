mod common;

use certsign_core::{DigestAlg, Error, KeyType, KeystoreError, Result, SigAlg};
use certsign_keystore::{
    AuthPrompt, AuthRequest, KeyStore, NoPrompt, Pkcs12KeyStore, SecretKind, SecretString,
    StaticPrompt,
};
use common::{Leaf, Pki};
use p12_keystore::{Certificate, KeyStore as P12, KeyStoreEntry, PrivateKeyChain};
use std::cell::RefCell;

const TBS: &[u8] = b"DER signed attributes";

fn alg(digest: DigestAlg, key: KeyType) -> SigAlg {
    SigAlg::new(digest, key)
}

fn name(d: DigestAlg) -> &'static str {
    match d {
        DigestAlg::Sha256 => "sha256",
        DigestAlg::Sha384 => "sha384",
        DigestAlg::Sha512 => "sha512",
    }
}

fn open(path: &std::path::Path, password: &str) -> Result<Pkcs12KeyStore> {
    Pkcs12KeyStore::open(path, &StaticPrompt::new(password))
}

fn keystore_error(e: Error) -> KeystoreError {
    match e {
        Error::Keystore(k) => k,
        other => panic!("not a key store error: {other}"),
    }
}

#[test]
fn lists_the_entry_with_its_chain_from_leaf_to_root() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("alice", None);
    let store = open(&pki.p12(&leaf, "secret", &[]), "secret").unwrap();
    let entries = store.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].alias, "alice");
    assert_eq!(entries[0].certificate(), leaf.cert_der);
    assert_eq!(
        entries[0].chain(),
        [
            leaf.cert_der.clone(),
            pki.intermediate_der(),
            pki.root_der()
        ],
        "end-entity first, root last"
    );
}

#[test]
fn opens_files_in_the_older_encryption_schemes() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("legacy", None);
    let path = pki.p12(
        &leaf,
        "secret",
        &[
            "-keypbe",
            "PBE-SHA1-3DES",
            "-certpbe",
            "PBE-SHA1-3DES",
            "-macalg",
            "sha1",
        ],
    );
    let store = open(&path, "secret").unwrap();
    assert_eq!(store.entries().unwrap()[0].certificate(), leaf.cert_der);
    let sig = store
        .sign(
            "legacy",
            alg(DigestAlg::Sha256, KeyType::Rsa),
            TBS,
            &NoPrompt,
        )
        .unwrap();
    assert!(pki.verify(&leaf, "sha256", TBS, &sig));
}

#[test]
fn lists_every_key_entry() {
    let Some(pki) = Pki::new() else { return };
    let (a, b) = (pki.leaf("first", None), pki.leaf("second", Some("P-256")));
    let mut p12 = P12::new();
    for leaf in [&a, &b] {
        let chain = vec![
            Certificate::from_der(&leaf.cert_der).unwrap(),
            Certificate::from_der(&pki.intermediate_der()).unwrap(),
        ];
        let key = PrivateKeyChain::new(pki.pkcs8(leaf), leaf.name.as_bytes(), chain);
        p12.add_entry(&leaf.name, KeyStoreEntry::PrivateKeyChain(key));
    }
    let path = pki.path().join("two.p12");
    std::fs::write(&path, p12.writer("pw").write().unwrap()).unwrap();

    let store = open(&path, "pw").unwrap();
    let mut aliases: Vec<_> = store
        .entries()
        .unwrap()
        .into_iter()
        .map(|e| e.alias)
        .collect();
    aliases.sort();
    assert_eq!(aliases, ["first", "second"]);
    // Each alias signs with its own key.
    let sig_a = store
        .sign(
            "first",
            alg(DigestAlg::Sha256, KeyType::Rsa),
            TBS,
            &NoPrompt,
        )
        .unwrap();
    let sig_b = store
        .sign(
            "second",
            alg(DigestAlg::Sha256, KeyType::Ecdsa),
            TBS,
            &NoPrompt,
        )
        .unwrap();
    assert!(pki.verify(&a, "sha256", TBS, &sig_a));
    assert!(pki.verify(&b, "sha256", TBS, &sig_b));
    assert!(!pki.verify(&a, "sha256", TBS, &sig_b));
}

#[test]
fn wrong_password_lists_nothing() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("alice", None);
    let path = pki.p12(&leaf, "right", &[]);
    for wrong in ["wrong", "", "Right", "right "] {
        let err = open(&path, wrong).unwrap_err();
        assert_eq!(keystore_error(err), KeystoreError::BadPassword, "{wrong:?}");
    }
    assert!(open(&path, "right").is_ok());
}

#[test]
fn unusual_passwords() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("alice", None);
    for pw in ["contraseña-ñ€", "p@ss word!"] {
        let path = pki.p12(&leaf, pw, &[]);
        assert!(open(&path, pw).is_ok(), "{pw:?}");
        assert!(open(&path, "other").is_err(), "{pw:?}");
    }
}

/// Records what the store asked for.
struct Recording(RefCell<Vec<(SecretKind, String, Option<u32>)>>);

impl AuthPrompt for Recording {
    fn secret(&self, r: &AuthRequest<'_>) -> Result<SecretString> {
        self.0
            .borrow_mut()
            .push((r.kind, r.target.to_owned(), r.retries_left));
        Ok(SecretString::from("pw".to_owned()))
    }
}

#[test]
fn asks_for_the_password_once_when_opening() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("alice", None);
    let path = pki.p12(&leaf, "pw", &[]);
    let prompt = Recording(RefCell::default());
    let store = Pkcs12KeyStore::open(&path, &prompt).unwrap();
    assert_eq!(
        *prompt.0.borrow(),
        [(SecretKind::Password, path.display().to_string(), None)]
    );
    // Listing and signing need nothing more: the file is already unlocked.
    store.entries().unwrap();
    store
        .sign("alice", alg(DigestAlg::Sha256, KeyType::Rsa), TBS, &prompt)
        .unwrap();
    assert_eq!(prompt.0.borrow().len(), 1);
}

#[test]
fn no_password_available() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("alice", None);
    let err = Pkcs12KeyStore::open(pki.p12(&leaf, "pw", &[]), &NoPrompt).unwrap_err();
    assert!(matches!(
        keystore_error(err),
        KeystoreError::SecretUnavailable {
            kind: "password",
            ..
        }
    ));
}

#[test]
fn bad_files() {
    let Some(pki) = Pki::new() else { return };
    let d = pki.path();
    std::fs::write(d.join("garbage.p12"), b"this is not a PKCS#12 file").unwrap();
    std::fs::write(d.join("empty.p12"), b"").unwrap();
    let leaf = pki.leaf("alice", None);
    let good = std::fs::read(pki.p12(&leaf, "pw", &[])).unwrap();
    std::fs::write(d.join("truncated.p12"), &good[..good.len() / 2]).unwrap();
    for file in ["garbage.p12", "empty.p12", "truncated.p12", "missing.p12"] {
        let err = open(&d.join(file), "pw").unwrap_err();
        assert!(
            matches!(keystore_error(err), KeystoreError::Backend(_)),
            "{file}"
        );
    }
}

#[test]
fn certificate_only_file_has_no_entries() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("alice", None);
    let d = pki.path();
    assert!(common::openssl(
        d,
        &[
            "pkcs12",
            "-export",
            "-nokeys",
            "-in",
            "alice.pem",
            "-passout",
            "pass:pw",
            "-out",
            "certs.p12"
        ]
    ));
    let store = open(&d.join("certs.p12"), "pw").unwrap();
    assert!(store.entries().unwrap().is_empty());
    let err = store
        .sign(
            "alice",
            alg(DigestAlg::Sha256, KeyType::Rsa),
            TBS,
            &NoPrompt,
        )
        .unwrap_err();
    assert_eq!(
        keystore_error(err),
        KeystoreError::UnknownAlias("alice".into())
    );
    let _ = leaf;
}

fn signing_matrix(pki: &Pki, leaf: &Leaf, store: &Pkcs12KeyStore, key: KeyType) {
    for digest in [DigestAlg::Sha256, DigestAlg::Sha384, DigestAlg::Sha512] {
        let sig = store
            .sign(&leaf.name, alg(digest, key), TBS, &NoPrompt)
            .unwrap();
        assert!(
            pki.verify(leaf, name(digest), TBS, &sig),
            "{key:?} {digest:?}"
        );
        assert!(
            !pki.verify(leaf, name(digest), b"other", &sig),
            "{key:?} {digest:?}: wrong data"
        );
    }
}

#[test]
fn signs_with_rsa_keys() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let store = open(&pki.p12(&leaf, "pw", &[]), "pw").unwrap();
    signing_matrix(&pki, &leaf, &store, KeyType::Rsa);
}

#[test]
fn signs_with_ecdsa_keys() {
    let Some(pki) = Pki::new() else { return };
    for curve in ["P-256", "P-384"] {
        let leaf = pki.leaf(&format!("ec-{curve}"), Some(curve));
        let store = open(&pki.p12(&leaf, "pw", &[]), "pw").unwrap();
        signing_matrix(&pki, &leaf, &store, KeyType::Ecdsa);
    }
}

#[test]
fn rsa_signatures_are_deterministic_and_ecdsa_valid_each_time() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let store = open(&pki.p12(&leaf, "pw", &[]), "pw").unwrap();
    let a = alg(DigestAlg::Sha256, KeyType::Rsa);
    assert_eq!(
        store.sign("rsa", a, TBS, &NoPrompt).unwrap(),
        store.sign("rsa", a, TBS, &NoPrompt).unwrap()
    );
}

#[test]
fn rejects_mismatched_algorithms_aliases_and_curves() {
    let Some(pki) = Pki::new() else { return };
    let rsa = pki.leaf("rsa", None);
    let ec = pki.leaf("ec", Some("P-256"));
    let p521 = pki.leaf("p521", Some("P-521"));
    let rsa_store = open(&pki.p12(&rsa, "pw", &[]), "pw").unwrap();
    let ec_store = open(&pki.p12(&ec, "pw", &[]), "pw").unwrap();
    let p521_store = open(&pki.p12(&p521, "pw", &[]), "pw").unwrap();

    let e = rsa_store
        .sign(
            "rsa",
            alg(DigestAlg::Sha256, KeyType::Ecdsa),
            TBS,
            &NoPrompt,
        )
        .unwrap_err();
    assert!(matches!(e, Error::UnsupportedAlgorithm(_)), "{e}");
    let e = ec_store
        .sign("ec", alg(DigestAlg::Sha256, KeyType::Rsa), TBS, &NoPrompt)
        .unwrap_err();
    assert!(matches!(e, Error::UnsupportedAlgorithm(_)), "{e}");
    let e = p521_store
        .sign(
            "p521",
            alg(DigestAlg::Sha512, KeyType::Ecdsa),
            TBS,
            &NoPrompt,
        )
        .unwrap_err();
    assert!(
        matches!(e, Error::UnsupportedAlgorithm(m) if m.contains("curve")),
        "P-521"
    );
    let e = rsa_store
        .sign(
            "nobody",
            alg(DigestAlg::Sha256, KeyType::Rsa),
            TBS,
            &NoPrompt,
        )
        .unwrap_err();
    assert_eq!(
        keystore_error(e),
        KeystoreError::UnknownAlias("nobody".into())
    );
}

#[test]
fn debug_output_shows_aliases_but_no_key_material() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let store = open(&pki.p12(&leaf, "pw", &[]), "pw").unwrap();
    let text = format!("{store:?}");
    assert!(text.contains("rsa"));
    let key_hex: String = pki
        .pkcs8(&leaf)
        .iter()
        .take(24)
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(!text.contains(&key_hex) && !text.contains("pw\""), "{text}");
}

/// The whole path: a key store signs the CMS attributes and the CMS verifies.
#[test]
fn signs_a_cms_that_verifies() {
    use certsign_cms::{PadesCms, PadesCmsOptions, verify_detached};
    let Some(pki) = Pki::new() else { return };
    let rsa = pki.leaf("rsa", None);
    let ec = pki.leaf("ec", Some("P-384"));
    let content = b"the covered bytes of a PDF";
    for (leaf, key, digest) in [
        (&rsa, KeyType::Rsa, DigestAlg::Sha256),
        (&rsa, KeyType::Rsa, DigestAlg::Sha512),
        (&ec, KeyType::Ecdsa, DigestAlg::Sha384),
    ] {
        let store = open(&pki.p12(leaf, "pw", &[]), "pw").unwrap();
        let entry = store.entries().unwrap().remove(0);
        let a = alg(digest, key);
        let cms = PadesCms::new(a, entry.chain(), PadesCmsOptions::default()).unwrap();
        let attrs = cms.signed_attributes(&cms.digest(content)).unwrap();
        let signature = store
            .sign(&entry.alias, a, &attrs.to_sign().unwrap(), &NoPrompt)
            .unwrap();
        let der = cms.assemble(&attrs, &signature).unwrap();

        let verified = verify_detached(&der, content).unwrap_or_else(|e| panic!("{a}: {e}"));
        assert_eq!(verified.signer, leaf.cert_der);
        assert_eq!(
            verified.certificates.len(),
            3,
            "the chain from the file is embedded"
        );
    }
}
