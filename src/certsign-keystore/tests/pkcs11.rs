mod common;

use certsign_core::{DigestAlg, Error, KeyType, KeystoreError, Result, SigAlg};
use certsign_keystore::{
    AuthPrompt, AuthRequest, KeyStore, NoPrompt, Pkcs11KeyStore, SecretKind, SecretString,
    StaticPrompt, default_module_candidates, detect_default_module,
};
use common::{Leaf, softhsm};
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

fn keystore_error(e: Error) -> KeystoreError {
    match e {
        Error::Keystore(k) => k,
        other => panic!("not a key store error: {other}"),
    }
}

fn pin() -> StaticPrompt {
    StaticPrompt::new(softhsm::USER_PIN)
}

/// Counts and records the prompts it receives.
struct Recording {
    answer: String,
    asked: RefCell<Vec<(SecretKind, String, Option<u32>)>>,
}

impl Recording {
    fn new(answer: &str) -> Self {
        Self {
            answer: answer.to_owned(),
            asked: RefCell::default(),
        }
    }
}

impl AuthPrompt for Recording {
    fn secret(&self, r: &AuthRequest<'_>) -> Result<SecretString> {
        self.asked
            .borrow_mut()
            .push((r.kind, r.target.to_owned(), r.retries_left));
        Ok(SecretString::from(self.answer.clone()))
    }
}

macro_rules! fixture {
    () => {
        match softhsm::get() {
            Some(f) => f,
            None => return,
        }
    };
}

fn open(f: &softhsm::Fixture, slot: u64) -> Pkcs11KeyStore {
    Pkcs11KeyStore::open(&f.module, Some(slot)).unwrap()
}

#[test]
fn lists_signing_certificates_without_a_pin() {
    let f = fixture!();
    let store = open(f, f.main);
    assert_eq!(store.token_label(), "certsign-main");
    let mut entries = store.entries().unwrap();
    entries.sort_by(|a, b| a.alias.cmp(&b.alias));
    // The CA certificates on the token are not offered for signing.
    assert_eq!(
        entries.iter().map(|e| e.alias.as_str()).collect::<Vec<_>>(),
        ["ec256", "ec384", "rsa"]
    );
    assert_eq!(entries[2].certificate(), f.rsa.cert_der);
    assert_eq!(entries[0].certificate(), f.ec256.cert_der);
}

#[test]
fn chains_run_from_leaf_to_root() {
    let f = fixture!();
    let entries = open(f, f.main).entries().unwrap();
    let rsa = entries.iter().find(|e| e.alias == "rsa").unwrap();
    assert_eq!(
        rsa.chain(),
        [
            f.rsa.cert_der.clone(),
            f.pki.intermediate_der(),
            f.pki.root_der()
        ],
        "the issuers kept on the token follow the certificate"
    );
}

#[test]
fn choosing_a_token() {
    let f = fixture!();
    // Several tokens are present: asking for none in particular is ambiguous.
    let err = Pkcs11KeyStore::open(&f.module, None).unwrap_err();
    let msg = keystore_error(err).to_string();
    assert!(
        msg.contains("several tokens") && msg.contains("certsign-main"),
        "{msg}"
    );
    // A slot that has no token.
    let err = Pkcs11KeyStore::open(&f.module, Some(999_999)).unwrap_err();
    assert!(keystore_error(err).to_string().contains("999999"));
    // An empty token lists nothing.
    assert!(open(f, f.empty).entries().unwrap().is_empty());
}

#[test]
fn signing_asks_for_the_pin_and_logs_out_afterwards() {
    let f = fixture!();
    let store = open(f, f.main);
    let prompt = Recording::new(softhsm::USER_PIN);
    assert!(
        prompt.asked.borrow().is_empty(),
        "opening and listing never ask"
    );
    store.entries().unwrap();
    assert!(prompt.asked.borrow().is_empty());

    let a = alg(DigestAlg::Sha256, KeyType::Rsa);
    store.sign("rsa", a, TBS, &prompt).unwrap();
    assert_eq!(
        *prompt.asked.borrow(),
        [(SecretKind::Pin, "certsign-main".to_owned(), None)]
    );
    // Logged out again: the next signature asks again.
    store.sign("rsa", a, TBS, &prompt).unwrap();
    assert_eq!(prompt.asked.borrow().len(), 2);
}

fn matrix(f: &softhsm::Fixture, leaf: &Leaf, key: KeyType) {
    let store = open(f, f.main);
    for digest in [DigestAlg::Sha256, DigestAlg::Sha384, DigestAlg::Sha512] {
        let sig = store
            .sign(&leaf.name, alg(digest, key), TBS, &pin())
            .unwrap();
        assert!(
            f.pki.verify(leaf, name(digest), TBS, &sig),
            "{} {digest:?}",
            leaf.name
        );
        assert!(
            !f.pki.verify(leaf, name(digest), b"other", &sig),
            "{} {digest:?}: other data",
            leaf.name
        );
    }
}

#[test]
fn signs_with_an_rsa_key_on_the_token() {
    let f = fixture!();
    matrix(f, &f.rsa, KeyType::Rsa);
}

#[test]
fn signs_with_ec_keys_and_returns_der() {
    let f = fixture!();
    matrix(f, &f.ec256, KeyType::Ecdsa);
    matrix(f, &f.ec384, KeyType::Ecdsa);
    // The token's raw r||s was turned into DER: it starts with a SEQUENCE.
    let sig = open(f, f.main)
        .sign("ec256", alg(DigestAlg::Sha256, KeyType::Ecdsa), TBS, &pin())
        .unwrap();
    assert_eq!(sig[0], 0x30);
    assert_eq!(sig[1] as usize, sig.len() - 2);
}

#[test]
fn missing_pin_and_bad_requests() {
    let f = fixture!();
    let store = open(f, f.main);
    let a = alg(DigestAlg::Sha256, KeyType::Rsa);
    let err = store.sign("rsa", a, TBS, &NoPrompt).unwrap_err();
    assert!(matches!(
        keystore_error(err),
        KeystoreError::SecretUnavailable { kind: "PIN", .. }
    ));
    let err = store.sign("nobody", a, TBS, &pin()).unwrap_err();
    assert_eq!(
        keystore_error(err),
        KeystoreError::UnknownAlias("nobody".into())
    );
    // An algorithm of the other key type, caught before the PIN is asked for.
    let prompt = Recording::new(softhsm::USER_PIN);
    let err = store
        .sign("rsa", alg(DigestAlg::Sha256, KeyType::Ecdsa), TBS, &prompt)
        .unwrap_err();
    assert!(matches!(err, Error::UnsupportedAlgorithm(_)), "{err}");
    assert!(prompt.asked.borrow().is_empty());
}

#[test]
fn a_wrong_pin_is_a_bad_pin_error() {
    let f = fixture!();
    let store = open(f, f.pin_tokens[0]);
    let a = alg(DigestAlg::Sha256, KeyType::Rsa);
    let e = store
        .sign("pin-leaf", a, TBS, &StaticPrompt::new("0000"))
        .unwrap_err();
    // SoftHSM2 never sets the token's final-try flag, so no count is reported; a token that does
    // set it reports one try left (see the unit tests in the module).
    assert!(matches!(
        keystore_error(e),
        KeystoreError::BadPin { retries_left: None }
            | KeystoreError::BadPin {
                retries_left: Some(1)
            }
    ));
}

#[test]
fn a_good_pin_after_a_bad_one_works() {
    let f = fixture!();
    let store = open(f, f.pin_tokens[1]);
    let a = alg(DigestAlg::Sha256, KeyType::Rsa);
    for _ in 0..2 {
        assert!(
            store
                .sign("pin-leaf", a, TBS, &StaticPrompt::new("0000"))
                .is_err()
        );
    }
    let sig = store.sign("pin-leaf", a, TBS, &pin()).unwrap();
    assert!(!sig.is_empty());
}

#[test]
fn a_failed_login_leaves_nothing_logged_in() {
    let f = fixture!();
    let store = open(f, f.pin_tokens[2]);
    let a = alg(DigestAlg::Sha256, KeyType::Rsa);
    assert!(
        store
            .sign("pin-leaf", a, TBS, &StaticPrompt::new("0000"))
            .is_err()
    );
    // The next signature has to ask for the PIN again.
    let prompt = Recording::new(softhsm::USER_PIN);
    store.sign("pin-leaf", a, TBS, &prompt).unwrap();
    assert_eq!(prompt.asked.borrow().len(), 1);
}

#[test]
fn only_certificates_with_a_visible_key_are_listed_when_the_token_shows_keys() {
    let f = fixture!();
    let store = open(f, f.visible);
    let aliases: Vec<_> = store
        .entries()
        .unwrap()
        .into_iter()
        .map(|e| e.alias)
        .collect();
    assert_eq!(
        aliases,
        ["visible-ec"],
        "the certificate without a key is left out"
    );
    // And the visible key works.
    let sig = store
        .sign(
            "visible-ec",
            alg(DigestAlg::Sha256, KeyType::Ecdsa),
            TBS,
            &pin(),
        )
        .unwrap();
    assert!(f.pki.verify(&f.visible_leaf, "sha256", TBS, &sig));
}

#[test]
fn two_stores_share_one_loaded_module() {
    let f = fixture!();
    let one = open(f, f.main);
    let two = open(f, f.visible);
    drop(one);
    // Dropping one store must not finalize the module under the other.
    assert!(
        two.sign(
            "visible-ec",
            alg(DigestAlg::Sha256, KeyType::Ecdsa),
            TBS,
            &pin()
        )
        .is_ok()
    );
    let three = open(f, f.main);
    assert!(
        three
            .sign("rsa", alg(DigestAlg::Sha256, KeyType::Rsa), TBS, &pin())
            .is_ok()
    );
}

#[test]
fn a_missing_module_is_a_clear_error() {
    let err = Pkcs11KeyStore::open("/nonexistent/libnothing.so", None).unwrap_err();
    assert!(
        keystore_error(err)
            .to_string()
            .contains("/nonexistent/libnothing.so")
    );
}

#[test]
fn the_default_module_search() {
    let candidates = default_module_candidates();
    assert!(!candidates.is_empty());
    assert!(
        candidates
            .iter()
            .all(|p| p.to_string_lossy().contains("opensc-pkcs11"))
    );
    // With no module named and OpenSC absent, the error lists where it looked.
    if detect_default_module().is_none() {
        let err = Pkcs11KeyStore::open("", None).unwrap_err();
        let msg = keystore_error(err).to_string();
        assert!(msg.contains("opensc-pkcs11"), "{msg}");
    }
}

/// The whole path: the token signs the CMS attributes and the CMS verifies.
#[test]
fn signs_a_cms_that_verifies() {
    use certsign_cms::{PadesCms, PadesCmsOptions, verify_detached};
    let f = fixture!();
    let store = open(f, f.main);
    let content = b"the covered bytes of a PDF";
    for (alias, key, digest, leaf) in [
        ("rsa", KeyType::Rsa, DigestAlg::Sha256, &f.rsa),
        ("ec256", KeyType::Ecdsa, DigestAlg::Sha256, &f.ec256),
        ("ec384", KeyType::Ecdsa, DigestAlg::Sha384, &f.ec384),
    ] {
        let entry = store
            .entries()
            .unwrap()
            .into_iter()
            .find(|e| e.alias == alias)
            .unwrap();
        let a = alg(digest, key);
        let cms = PadesCms::new(a, entry.chain(), PadesCmsOptions::default()).unwrap();
        let attrs = cms.signed_attributes(&cms.digest(content)).unwrap();
        let signature = store
            .sign(alias, a, &attrs.to_sign().unwrap(), &pin())
            .unwrap();
        let der = cms.assemble(&attrs, &signature).unwrap();
        let verified = verify_detached(&der, content).unwrap_or_else(|e| panic!("{alias}: {e}"));
        assert_eq!(verified.signer, leaf.cert_der);
    }
}
