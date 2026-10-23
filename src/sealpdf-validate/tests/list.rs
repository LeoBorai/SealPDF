mod common;

use common::*;
use sealpdf_core::{ValidityError, Verdict};
use sealpdf_validate::{inspect, signature_count};

#[test]
fn counts_signatures_without_timestamps() {
    let Some(pki) = Pki::new() else { return };
    let alice = pki.leaf("Alice", None);
    let bob = pki.leaf("Bob", None);
    let blank = blank_pdf(1, false);
    let once = sign(&blank, &store(&pki, &alice), "Alice");
    let twice = sign(&once, &store(&pki, &bob), "Bob");
    let token = cms_of(&once, 0);

    assert_eq!(signature_count(&open(blank.clone())), 0);
    assert_eq!(signature_count(&open(unsigned_field_pdf())), 0);
    assert_eq!(signature_count(&open(once.clone())), 1);
    assert_eq!(signature_count(&open(twice)), 2);
    // A document timestamp is not a signature, with or without one beside it.
    assert_eq!(signature_count(&open(timestamp_only_pdf(&token))), 0);
    assert_eq!(signature_count(&open(with_doc_timestamp(&once, &token))), 1);
}

#[test]
fn lists_a_co_signed_pdf_oldest_first() {
    let Some(pki) = Pki::new() else { return };
    let alice = pki.leaf("Alice", None);
    let bob = pki.leaf("Bob", None);
    let once = sign(&blank_pdf(1, false), &store(&pki, &alice), "Alice");
    let twice = sign(&once, &store(&pki, &bob), "Bob");

    let report = inspect(&open(twice), &now()).unwrap();
    assert_eq!(report.revisions, 3);
    let who: Vec<_> = report
        .signatures
        .iter()
        .map(|s| (s.signer.as_deref(), s.revision, s.is_intact()))
        .collect();
    assert_eq!(who, vec![(Some("Alice"), 2, true), (Some("Bob"), 3, true)]);
    let first = &report.signatures[0];
    assert_eq!(first.field, "Signature1");
    assert_eq!(first.page, Some(1));
    assert_eq!(first.sub_filter.as_deref(), Some("adbe.pkcs7.detached"));
    assert_eq!(first.signed_at.as_deref(), Some("2024-05-17T10:30:00Z"));
    assert!(!first.doc_timestamp);
    assert_eq!(report.signatures[1].field, "Signature2");
    assert_eq!(report.verdicts, vec![Verdict::OK]);
    assert!(report.is_ok());
}

#[test]
fn an_unsigned_field_is_not_listed() {
    let report = inspect(&open(unsigned_field_pdf()), &now()).unwrap();
    assert!(report.signatures.is_empty());
    assert_eq!(report.verdicts, vec![Verdict::ko(ValidityError::NoSign)]);
}

#[test]
fn a_signature_without_a_readable_cms_is_still_listed() {
    let Some(pki) = Pki::new() else { return };
    let alice = pki.leaf("Alice", None);
    let signed = sign(&blank_pdf(1, false), &store(&pki, &alice), "Alice");
    let broken = put_contents(&signed, 0, b"this is not a CMS");

    let report = inspect(&open(broken), &now()).unwrap();
    assert_eq!(report.signatures.len(), 1);
    assert_eq!(
        report.signatures[0].status,
        vec![ValidityError::CorruptedSign]
    );
    assert_eq!(report.signatures[0].revision, 2);
    assert_eq!(
        report.verdicts,
        vec![Verdict::ko(ValidityError::CorruptedSign)]
    );
}
