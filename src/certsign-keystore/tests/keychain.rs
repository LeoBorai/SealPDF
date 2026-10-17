mod common;

use certsign_core::{Error, KeystoreError};
use certsign_keystore::KeychainKeyStore;

fn keystore_error(e: Error) -> KeystoreError {
    match e {
        Error::Keystore(k) => k,
        other => panic!("not a key store error: {other}"),
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn the_keychain_exists_only_on_macos() {
    for result in [
        KeychainKeyStore::open(),
        KeychainKeyStore::open_in(std::path::Path::new("x.keychain-db")),
    ] {
        let err = result.unwrap_err();
        let msg = keystore_error(err).to_string();
        assert!(msg.contains("only on macOS"), "{msg}");
    }
}

/// Tests of the real Keychain. They build a throwaway keychain file, so the user's own keychains
/// are never read or changed. They run only on macOS (the macOS CI job runs them).
#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use certsign_cms::{PadesCms, PadesCmsOptions, verify_detached};
    use certsign_core::{DigestAlg, KeyType, SigAlg};
    use certsign_keystore::{KeyStore, NoPrompt};
    use common::{Leaf, Pki};
    use std::{path::PathBuf, process::Command};

    const PASSWORD: &str = "certsign-test";

    fn security(args: &[&str]) {
        let out = Command::new("security")
            .args(args)
            .output()
            .expect("the `security` tool");
        assert!(
            out.status.success(),
            "security {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A temporary keychain holding `leaves`, deleted when dropped.
    struct TempKeychain {
        path: PathBuf,
    }

    impl TempKeychain {
        fn new(pki: &Pki, leaves: &[&Leaf]) -> Self {
            let path = pki.path().join("test.keychain-db");
            let p = path.to_str().unwrap();
            security(&["create-keychain", "-p", PASSWORD, p]);
            security(&["set-keychain-settings", p]);
            security(&["unlock-keychain", "-p", PASSWORD, p]);
            for leaf in leaves {
                // The older PKCS#12 encryption: macOS cannot read what OpenSSL 3 writes by default.
                let file = pki.p12(
                    leaf,
                    "p12pass",
                    &[
                        "-keypbe",
                        "PBE-SHA1-3DES",
                        "-certpbe",
                        "PBE-SHA1-3DES",
                        "-macalg",
                        "sha1",
                    ],
                );
                // `-A` lets any application use the key, so the tests never wait on a prompt.
                security(&[
                    "import",
                    file.to_str().unwrap(),
                    "-k",
                    p,
                    "-P",
                    "p12pass",
                    "-A",
                ]);
            }
            security(&[
                "set-key-partition-list",
                "-S",
                "apple-tool:,apple:,codesign:",
                "-s",
                "-k",
                PASSWORD,
                p,
            ]);
            Self { path }
        }

        fn open(&self) -> KeychainKeyStore {
            KeychainKeyStore::open_in(&self.path).unwrap()
        }
    }

    impl Drop for TempKeychain {
        fn drop(&mut self) {
            let _ = Command::new("security")
                .args(["delete-keychain", self.path.to_str().unwrap()])
                .output();
        }
    }

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

    #[test]
    fn lists_identities_with_their_chains() {
        let Some(pki) = Pki::new() else { return };
        let (rsa, ec) = (pki.leaf("rsa", None), pki.leaf("ec", Some("P-256")));
        let keychain = TempKeychain::new(&pki, &[&rsa, &ec]);
        let entries = keychain.open().entries().unwrap();
        let mut aliases: Vec<_> = entries.iter().map(|e| e.alias.as_str()).collect();
        aliases.sort();
        assert_eq!(aliases, ["ec", "rsa"]);
        let rsa_entry = entries.iter().find(|e| e.alias == "rsa").unwrap();
        assert_eq!(rsa_entry.certificate(), rsa.cert_der);
        assert_eq!(
            rsa_entry.chain(),
            [rsa.cert_der.clone(), pki.intermediate_der(), pki.root_der()],
            "signing certificate first, root last"
        );
    }

    #[test]
    fn signs_with_rsa_and_ec_keys() {
        let Some(pki) = Pki::new() else { return };
        let rsa = pki.leaf("rsa", None);
        let p256 = pki.leaf("p256", Some("P-256"));
        let p384 = pki.leaf("p384", Some("P-384"));
        let keychain = TempKeychain::new(&pki, &[&rsa, &p256, &p384]);
        let store = keychain.open();
        let tbs = b"DER signed attributes";
        for (leaf, key) in [
            (&rsa, KeyType::Rsa),
            (&p256, KeyType::Ecdsa),
            (&p384, KeyType::Ecdsa),
        ] {
            for digest in [DigestAlg::Sha256, DigestAlg::Sha384, DigestAlg::Sha512] {
                let sig = store
                    .sign(&leaf.name, alg(digest, key), tbs, &NoPrompt)
                    .unwrap();
                assert!(
                    pki.verify(leaf, name(digest), tbs, &sig),
                    "{} {digest:?}",
                    leaf.name
                );
                assert!(!pki.verify(leaf, name(digest), b"other", &sig));
            }
        }
    }

    #[test]
    fn rejects_bad_requests() {
        let Some(pki) = Pki::new() else { return };
        let rsa = pki.leaf("rsa", None);
        let keychain = TempKeychain::new(&pki, &[&rsa]);
        let store = keychain.open();
        let e = store
            .sign(
                "rsa",
                alg(DigestAlg::Sha256, KeyType::Ecdsa),
                b"x",
                &NoPrompt,
            )
            .unwrap_err();
        assert!(matches!(e, Error::UnsupportedAlgorithm(_)), "{e}");
        let e = store
            .sign(
                "nobody",
                alg(DigestAlg::Sha256, KeyType::Rsa),
                b"x",
                &NoPrompt,
            )
            .unwrap_err();
        assert_eq!(
            keystore_error(e),
            KeystoreError::UnknownAlias("nobody".into())
        );
        let e = KeychainKeyStore::open_in(std::path::Path::new("/nonexistent/none.keychain-db"))
            .unwrap_err();
        assert!(matches!(keystore_error(e), KeystoreError::Backend(_)));
    }

    #[test]
    fn signs_a_cms_that_verifies() {
        let Some(pki) = Pki::new() else { return };
        let rsa = pki.leaf("rsa", None);
        let keychain = TempKeychain::new(&pki, &[&rsa]);
        let store = keychain.open();
        let entry = store.entries().unwrap().remove(0);
        let content = b"the covered bytes of a PDF";
        let a = alg(DigestAlg::Sha256, KeyType::Rsa);
        let cms = PadesCms::new(a, entry.chain(), PadesCmsOptions::default()).unwrap();
        let attrs = cms.signed_attributes(&cms.digest(content)).unwrap();
        let signature = store
            .sign(&entry.alias, a, &attrs.to_sign().unwrap(), &NoPrompt)
            .unwrap();
        let der = cms.assemble(&attrs, &signature).unwrap();
        let verified = verify_detached(&der, content).unwrap();
        assert_eq!(verified.signer, rsa.cert_der);
    }
}
