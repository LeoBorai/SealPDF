use sealpdf_core::{Error, KeystoreError, Result, SigAlg};
use sealpdf_keystore::{
    AuthPrompt, AuthRequest, Entry, ExposeSecret, KeyStore, NoPrompt, SecretKind, SecretString,
    StaticPrompt,
};
use std::{cell::RefCell, str::FromStr};

#[test]
fn entry_keeps_the_chain_in_order() {
    let chain = vec![b"ee".to_vec(), b"intermediate".to_vec(), b"root".to_vec()];
    let e = Entry::new("alias", chain.clone()).unwrap();
    assert_eq!(e.alias, "alias");
    assert_eq!(e.certificate(), b"ee");
    assert_eq!(e.chain(), chain.as_slice());
    assert!(
        Entry::new("empty", vec![]).is_none(),
        "an entry has at least its certificate"
    );
}

#[test]
fn static_prompt_answers_every_request() {
    let p = StaticPrompt::new("s3cret");
    for kind in [SecretKind::Password, SecretKind::Pin] {
        let got = p.secret(&AuthRequest::new(kind, "token")).unwrap();
        assert_eq!(got.expose_secret(), "s3cret");
    }
    assert!(!format!("{p:?}").contains("s3cret"));
}

#[test]
fn no_prompt_reports_a_missing_secret() {
    let err = NoPrompt
        .secret(&AuthRequest::new(SecretKind::Pin, "DNIe"))
        .unwrap_err();
    match err {
        Error::Keystore(KeystoreError::SecretUnavailable { kind, reason }) => {
            assert_eq!(kind, "PIN");
            assert!(reason.contains("DNIe"), "{reason}");
        }
        other => panic!("{other}"),
    }
}

#[test]
fn keystore_errors_read_well() {
    assert_eq!(KeystoreError::BadPassword.to_string(), "wrong password");
    assert_eq!(
        KeystoreError::BadPin { retries_left: None }.to_string(),
        "wrong PIN"
    );
    assert_eq!(
        KeystoreError::BadPin {
            retries_left: Some(2)
        }
        .to_string(),
        "wrong PIN (2 tries left)"
    );
    assert_eq!(
        KeystoreError::BadPin {
            retries_left: Some(1)
        }
        .to_string(),
        "wrong PIN (1 try left)"
    );
    assert_eq!(
        KeystoreError::UnknownAlias("x".into()).to_string(),
        "no key store entry with alias \"x\""
    );
    let wrapped: Error = KeystoreError::BadPassword.into();
    assert_eq!(wrapped.to_string(), "key store: wrong password");
}

/// A token-like store: listing needs no secret, signing asks for the PIN, a wrong PIN counts down.
struct FakeToken {
    pin: &'static str,
    retries: RefCell<u32>,
}

impl KeyStore for FakeToken {
    fn entries(&self) -> Result<Vec<Entry>> {
        Ok(vec![
            Entry::new("CertFirmaDigital", vec![b"cert".to_vec()]).unwrap(),
        ])
    }

    fn sign(
        &self,
        alias: &str,
        _alg: SigAlg,
        tbs: &[u8],
        auth: &dyn AuthPrompt,
    ) -> Result<Vec<u8>> {
        if alias != "CertFirmaDigital" {
            return Err(KeystoreError::UnknownAlias(alias.into()).into());
        }
        let retries = *self.retries.borrow();
        let request = AuthRequest {
            kind: SecretKind::Pin,
            target: "fake token",
            retries_left: Some(retries),
        };
        let given = auth.secret(&request)?;
        if given.expose_secret() != self.pin {
            *self.retries.borrow_mut() -= 1;
            return Err(KeystoreError::BadPin {
                retries_left: Some(retries - 1),
            }
            .into());
        }
        Ok(tbs.iter().rev().copied().collect())
    }
}

/// Records how often and how it was asked.
struct Recording {
    answer: &'static str,
    seen: RefCell<Vec<(SecretKind, String, Option<u32>)>>,
}

impl AuthPrompt for Recording {
    fn secret(&self, r: &AuthRequest<'_>) -> Result<SecretString> {
        self.seen
            .borrow_mut()
            .push((r.kind, r.target.to_owned(), r.retries_left));
        Ok(SecretString::from(self.answer.to_owned()))
    }
}

#[test]
fn a_store_asks_for_the_pin_only_when_signing() {
    let store: Box<dyn KeyStore> = Box::new(FakeToken {
        pin: "1234",
        retries: RefCell::new(3),
    });
    let prompt = Recording {
        answer: "1234",
        seen: RefCell::default(),
    };
    let alg = SigAlg::from_str("SHA256withRSA").unwrap();

    // Listing certificates needs no PIN.
    assert_eq!(store.entries().unwrap().len(), 1);
    assert!(prompt.seen.borrow().is_empty(), "no prompt for a listing");

    let sig = store
        .sign("CertFirmaDigital", alg, b"abc", &prompt)
        .unwrap();
    assert_eq!(sig, b"cba");
    assert_eq!(
        *prompt.seen.borrow(),
        vec![(SecretKind::Pin, "fake token".to_owned(), Some(3))]
    );
}

#[test]
fn wrong_pin_reports_the_retries_left() {
    let store = FakeToken {
        pin: "1234",
        retries: RefCell::new(3),
    };
    let wrong = Recording {
        answer: "0000",
        seen: RefCell::default(),
    };
    let alg = SigAlg::from_str("SHA256withRSA").unwrap();

    let err = store
        .sign("CertFirmaDigital", alg, b"x", &wrong)
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::Keystore(KeystoreError::BadPin {
                retries_left: Some(2)
            })
        ),
        "{err}"
    );
    let err = store
        .sign("CertFirmaDigital", alg, b"x", &wrong)
        .unwrap_err();
    assert_eq!(err.to_string(), "key store: wrong PIN (1 try left)");
    // The prompt is told how many tries remain, so it can warn the user.
    let last = wrong.seen.borrow().last().cloned().unwrap();
    assert_eq!(last.2, Some(2));
}

#[test]
fn unknown_alias_and_missing_secret_are_distinct() {
    let store = FakeToken {
        pin: "1234",
        retries: RefCell::new(3),
    };
    let alg = SigAlg::from_str("SHA256withRSA").unwrap();
    let err = store.sign("other", alg, b"x", &NoPrompt).unwrap_err();
    assert!(
        matches!(err, Error::Keystore(KeystoreError::UnknownAlias(_))),
        "{err}"
    );
    let err = store
        .sign("CertFirmaDigital", alg, b"x", &NoPrompt)
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::Keystore(KeystoreError::SecretUnavailable { .. })
        ),
        "{err}"
    );
}
