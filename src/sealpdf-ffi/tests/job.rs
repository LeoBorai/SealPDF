mod common;

use common::{blank_pdf, make_p12};
use sealpdf_core::{Result, SigAlg};
use sealpdf_ffi::job::{default_box, sign_file, sign_file_visible};
use sealpdf_keystore::{AuthPrompt, Entry, KeyStore, Pkcs12KeyStore, StaticPrompt};
use sealpdf_pdf::{PdfDocument, default_signature_box};
use std::path::Path;

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

/// The page, rectangle and whether it has an appearance, for the last signature of the file.
fn last_widget(path: &Path) -> (Option<u32>, [f32; 4], bool) {
    let pdf = PdfDocument::open(std::fs::read(path).unwrap(), None).unwrap();
    let sig = pdf.signatures().pop().unwrap();
    let has_ap = pdf.document().get_dictionary(sig.id).unwrap().has(b"AP");
    (sig.page, sig.rect.unwrap(), has_ap)
}

#[test]
fn the_default_box_is_the_one_signing_uses() {
    let dir = tempfile::tempdir().unwrap();
    let pdf = dir.path().join("in.pdf");
    std::fs::write(&pdf, blank_pdf(3)).unwrap();

    let got = default_box(&pdf).unwrap();
    assert_eq!(got, (3, [36.0, 36.0, 236.0, 86.0]));
    let direct =
        default_signature_box(&PdfDocument::open(std::fs::read(&pdf).unwrap(), None).unwrap());
    assert_eq!(got, direct.unwrap());
}

#[test]
fn the_default_box_of_a_non_pdf_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk.pdf");
    std::fs::write(&junk, b"not a pdf").unwrap();
    assert!(default_box(&junk).is_err());
    assert!(
        default_box(&dir.path().join("missing.pdf"))
            .unwrap_err()
            .contains("cannot read")
    );
}

#[test]
fn a_visible_signature_goes_where_it_is_told() {
    let dir = tempfile::tempdir().unwrap();
    let Some(p12) = make_p12(dir.path(), "hunter2") else {
        return;
    };
    let store = Pkcs12KeyStore::open(p12, &StaticPrompt::new("hunter2")).unwrap();
    let alias = store.entries().unwrap()[0].alias.clone();
    let (input, output) = (dir.path().join("in.pdf"), dir.path().join("out.pdf"));
    std::fs::write(&input, blank_pdf(3)).unwrap();

    sign_file_visible(
        &input,
        &output,
        &alias,
        &store,
        2,
        [300.0, 400.0, 500.0, 460.0],
    )
    .unwrap();

    assert_eq!(
        last_widget(&output),
        (Some(2), [300.0, 400.0, 500.0, 460.0], true)
    );
}

#[test]
fn a_bad_place_leaves_no_output() {
    let dir = tempfile::tempdir().unwrap();
    let Some(p12) = make_p12(dir.path(), "hunter2") else {
        return;
    };
    let store = Pkcs12KeyStore::open(p12, &StaticPrompt::new("hunter2")).unwrap();
    let alias = store.entries().unwrap()[0].alias.clone();
    let (input, output) = (dir.path().join("in.pdf"), dir.path().join("out.pdf"));
    std::fs::write(&input, blank_pdf(1)).unwrap();

    for (page, rect) in [
        (1, [700.0, 900.0, 800.0, 950.0]),
        (4, [50.0, 50.0, 250.0, 100.0]),
    ] {
        assert!(sign_file_visible(&input, &output, &alias, &store, page, rect).is_err());
        assert!(!output.exists());
    }
}

#[test]
fn a_visible_signature_never_overwrites_the_input_either() {
    let dir = tempfile::tempdir().unwrap();
    let pdf = dir.path().join("a.pdf");
    std::fs::write(&pdf, b"original").unwrap();

    let err = sign_file_visible(
        &pdf,
        &dir.path().join(".").join("a.pdf"),
        "x",
        &Empty,
        1,
        [10.0, 10.0, 100.0, 50.0],
    )
    .unwrap_err();

    assert!(err.contains("never overwritten"), "{err}");
    assert_eq!(std::fs::read(&pdf).unwrap(), b"original");
}
