mod common;

use common::*;
use der::{
    Any,
    asn1::{OctetString, SetOfVec},
};
use sealpdf_core::{ValidityError, Verdict};
use sealpdf_validate::inspect;
use x509_cert::attr::Attribute;

fn verdicts(file: Vec<u8>) -> Vec<Verdict> {
    inspect(&open(file), &now()).unwrap().verdicts
}

fn alice(pki: &Pki) -> (Leaf, Vec<u8>) {
    let leaf = pki.leaf("Alice", None);
    let file = sign(&blank_pdf(1, false), &store(pki, &leaf), "Alice");
    (leaf, file)
}

#[test]
fn a_clean_signed_pdf_is_ok() {
    let Some(pki) = Pki::new() else { return };
    let (_, file) = alice(&pki);
    assert_eq!(verdicts(file), vec![Verdict::OK]);
}

#[test]
fn an_unsigned_pdf_has_no_signature() {
    let expected = vec![Verdict::ko(ValidityError::NoSign)];
    assert_eq!(verdicts(blank_pdf(1, false)), expected);
    assert_eq!(verdicts(unsigned_field_pdf()), expected);
}

#[test]
fn a_document_timestamp_alone_is_not_a_signature() {
    let Some(pki) = Pki::new() else { return };
    let (_, file) = alice(&pki);
    let report = inspect(&open(timestamp_only_pdf(&cms_of(&file, 0))), &now()).unwrap();
    assert_eq!(report.verdicts, vec![Verdict::ko(ValidityError::NoSign)]);
    assert_eq!(report.signatures.len(), 1, "the timestamp is still listed");
    assert!(report.signatures[0].doc_timestamp);
}

#[test]
fn a_revision_after_the_last_signature_is_unknown() {
    let Some(pki) = Pki::new() else { return };
    let (_, file) = alice(&pki);
    assert_eq!(
        verdicts(touch(&file)),
        vec![Verdict::unknown(ValidityError::ModifiedDocument)]
    );
}

#[test]
fn a_co_signed_pdf_has_no_later_revision() {
    let Some(pki) = Pki::new() else { return };
    let (_, once) = alice(&pki);
    let bob = pki.leaf("Bob", None);
    let twice = sign(&once, &store(&pki, &bob), "Bob");
    assert_eq!(verdicts(twice), vec![Verdict::OK]);
}

#[test]
fn ko_comes_before_unknown() {
    let Some(pki) = Pki::new() else { return };
    let (_, mut file) = alice(&pki);
    file[7] = b'4';
    assert_eq!(
        verdicts(touch(&file)),
        vec![
            Verdict::ko(ValidityError::NoMatchData),
            Verdict::unknown(ValidityError::ModifiedDocument),
        ]
    );
}

#[test]
fn the_same_error_twice_appears_once() {
    let Some(pki) = Pki::new() else { return };
    let (_, once) = alice(&pki);
    let bob = pki.leaf("Bob", None);
    let twice = sign(&once, &store(&pki, &bob), "Bob");
    assert_eq!(
        verdicts(twice.clone()),
        vec![Verdict::OK],
        "both are intact before the damage"
    );
    // Damage both: the first range covers the header, the second covers it too.
    let mut damaged = twice;
    damaged[7] = b'4';
    assert_eq!(
        verdicts(damaged),
        vec![Verdict::ko(ValidityError::NoMatchData)]
    );
}

#[test]
fn a_signature_timestamp_token_is_not_verified() {
    let Some(pki) = Pki::new() else { return };
    let (_, file) = alice(&pki);
    let stamped = edit_cms(&file, 0, |s| {
        let mut infos: Vec<_> = s.signer_infos.0.iter().cloned().collect();
        let token = Attribute {
            oid: const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14"),
            values: SetOfVec::try_from(vec![
                Any::encode_from(&OctetString::new(b"token".to_vec()).unwrap()).unwrap(),
            ])
            .unwrap(),
        };
        infos[0].unsigned_attrs = Some(SetOfVec::try_from(vec![token]).unwrap());
        s.signer_infos.0 = SetOfVec::try_from(infos).unwrap();
    });
    assert_eq!(
        verdicts(stamped),
        vec![Verdict::unknown(ValidityError::SignProfileNotChecked)]
    );
}

#[test]
fn validation_data_after_the_signature_is_unknown_twice() {
    let Some(pki) = Pki::new() else { return };
    let (_, file) = alice(&pki);
    assert_eq!(
        verdicts(with_dss(&file)),
        vec![
            Verdict::unknown(ValidityError::ModifiedDocument),
            Verdict::unknown(ValidityError::SignProfileNotChecked),
        ]
    );
}

#[test]
fn an_expired_certificate_yields_to_the_long_term_profile() {
    // signature, then validation data, then a document timestamp that covers both.
    let Some(pki) = Pki::new() else { return };
    let (_, file) = alice(&pki);
    let token = cms_of(&file, 0);
    let long_term = with_doc_timestamp(&with_dss(&file), &token);

    assert_eq!(
        verdicts(long_term.clone()),
        vec![Verdict::unknown(ValidityError::SignProfileNotChecked)]
    );
    let expired = inspect(&open(long_term), &at(2100)).unwrap();
    assert_eq!(
        expired.verdicts,
        vec![
            Verdict::unknown(ValidityError::SignProfileNotChecked),
            Verdict::ko(ValidityError::CertificateExpired),
        ]
    );
}

#[test]
fn a_signature_after_a_no_changes_certification_is_refused() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("Alice", None);
    let keys = store(&pki, &leaf);
    let certified = sign_unchecked(&blank_pdf(1, false), &keys, "Alice", Some(1));
    assert_eq!(open(certified.clone()).certification_level(), Some(1));
    assert_eq!(verdicts(certified.clone()), vec![Verdict::OK]);

    let approved = sign_unchecked(&certified, &keys, "Alice", None);
    assert_eq!(
        verdicts(approved),
        vec![Verdict::ko(ValidityError::CertifiedSignRevision)]
    );
}

#[test]
fn other_certification_levels_allow_later_signatures() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("Alice", None);
    let keys = store(&pki, &leaf);
    let certified = sign_unchecked(&blank_pdf(1, false), &keys, "Alice", Some(2));
    let approved = sign_unchecked(&certified, &keys, "Alice", None);
    assert_eq!(verdicts(approved), vec![Verdict::OK]);
}
