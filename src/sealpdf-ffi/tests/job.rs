use sealpdf_core::{Result, SigAlg};
use sealpdf_ffi::job::sign_file;
use sealpdf_keystore::{AuthPrompt, Entry, KeyStore};

/// A store with no certificates: enough to reach the checks that come before signing.
struct Empty;

impl KeyStore for Empty {
    fn entries(&self) -> Result<Vec<Entry>> {
        Ok(Vec::new())
    }

    fn sign(&self, _: &str, _: SigAlg, _: &[u8], _: &dyn AuthPrompt) -> Result<Vec<u8>> {
        unreachable!("nothing is signed in these tests")
    }
}

#[test]
fn the_input_is_never_the_output() {
    let dir = tempfile::tempdir().unwrap();
    let pdf = dir.path().join("a.pdf");
    std::fs::write(&pdf, b"original").unwrap();

    let err = sign_file(&pdf, &dir.path().join(".").join("a.pdf"), "x", &Empty).unwrap_err();

    assert!(err.contains("never overwritten"), "{err}");
    assert_eq!(std::fs::read(&pdf).unwrap(), b"original");
}

#[test]
fn a_file_that_is_not_a_pdf_leaves_no_output() {
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk.pdf");
    let out = dir.path().join("junk_signed.pdf");
    std::fs::write(&junk, b"not a pdf").unwrap();

    assert!(sign_file(&junk, &out, "x", &Empty).is_err());
    assert!(!out.exists());
}

#[test]
fn a_missing_input_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let err = sign_file(
        &dir.path().join("missing.pdf"),
        &dir.path().join("out.pdf"),
        "x",
        &Empty,
    )
    .unwrap_err();
    assert!(err.contains("cannot read"), "{err}");
}
