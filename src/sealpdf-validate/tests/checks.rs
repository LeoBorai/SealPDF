mod common;

use common::*;
use der::asn1::SetOfVec;
use sealpdf_core::{ValidityError, Verdict};
use sealpdf_validate::inspect;

fn signed(pki: &Pki, name: &str, curve: Option<&str>) -> Vec<u8> {
    let leaf = pki.leaf(name, curve);
    sign(&blank_pdf(1, false), &store(pki, &leaf), name)
}

#[test]
fn intact_signatures_of_every_key_type() {
    let Some(pki) = Pki::new() else { return };
    for (name, curve) in [
        ("rsa", None),
        ("p256", Some("P-256")),
        ("p384", Some("P-384")),
    ] {
        let report = inspect(&open(signed(&pki, name, curve)), &now()).unwrap();
        assert!(report.signatures[0].is_intact(), "{name}");
        assert_eq!(report.signatures[0].signer.as_deref(), Some(name));
        assert!(report.is_ok(), "{name}");
    }
}

#[test]
fn a_changed_signed_byte_does_not_match() {
    let Some(pki) = Pki::new() else { return };
    let mut file = signed(&pki, "Alice", None);
    assert_eq!(&file[..8], b"%PDF-1.5");
    file[7] = b'4'; // inside the covered range
    let report = inspect(&open(file), &now()).unwrap();
    assert_eq!(
        report.signatures[0].status,
        vec![ValidityError::NoMatchData]
    );
    assert_eq!(
        report.verdicts,
        vec![Verdict::ko(ValidityError::NoMatchData)]
    );
    // The signer is still named, from the file's own record of it.
    assert_eq!(report.signatures[0].signer.as_deref(), Some("Alice"));
}

#[test]
fn a_wrong_signature_value_does_not_match() {
    let Some(pki) = Pki::new() else { return };
    let file = signed(&pki, "Alice", None);
    let bad = edit_cms(&file, 0, |s| {
        let mut infos: Vec<_> = s.signer_infos.0.iter().cloned().collect();
        let mut value = infos[0].signature.as_bytes().to_vec();
        let last = value.len() - 1;
        value[last] ^= 1;
        infos[0].signature = der::asn1::OctetString::new(value).unwrap();
        s.signer_infos.0 = SetOfVec::try_from(infos).unwrap();
    });
    let report = inspect(&open(bad), &now()).unwrap();
    assert_eq!(
        report.signatures[0].status,
        vec![ValidityError::NoMatchData]
    );
}

#[test]
fn a_digest_algorithm_outside_the_allowed_set_is_refused() {
    let Some(pki) = Pki::new() else { return };
    let file = signed(&pki, "Alice", None);
    let sha1 = const_oid::ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
    let bad = edit_cms(&file, 0, |s| {
        let mut infos: Vec<_> = s.signer_infos.0.iter().cloned().collect();
        infos[0].digest_alg.oid = sha1;
        s.signer_infos.0 = SetOfVec::try_from(infos).unwrap();
    });
    let report = inspect(&open(bad), &now()).unwrap();
    assert_eq!(
        report.signatures[0].status,
        vec![ValidityError::AlgorithmNotSupported]
    );
}

#[test]
fn the_certificate_period_is_checked_against_the_clock() {
    let Some(pki) = Pki::new() else { return };
    let file = signed(&pki, "Alice", None);

    let late = inspect(&open(file.clone()), &at(2100)).unwrap();
    assert_eq!(
        late.signatures[0].status,
        vec![ValidityError::CertificateExpired]
    );
    assert_eq!(
        late.verdicts,
        vec![Verdict::ko(ValidityError::CertificateExpired)]
    );

    let early = inspect(&open(file), &at(2000)).unwrap();
    assert_eq!(
        early.signatures[0].status,
        vec![ValidityError::CertificateNotValidYet]
    );
}

#[test]
fn a_chain_that_no_one_trusts_is_still_intact() {
    // The test CA is in no trust store; trust is not part of the check.
    let Some(pki) = Pki::new() else { return };
    let report = inspect(&open(signed(&pki, "Alice", None)), &now()).unwrap();
    assert!(report.is_ok());
    assert!(!report.trust_checked);
}

#[test]
fn a_document_timestamp_is_checked_for_its_digest_algorithm_only() {
    let Some(pki) = Pki::new() else { return };
    let once = signed(&pki, "Alice", None);
    let token = cms_of(&once, 0);

    let stamped = with_doc_timestamp(&once, &token);
    let report = inspect(&open(stamped.clone()), &now()).unwrap();
    assert_eq!(report.signatures.len(), 2);
    assert!(report.signatures[1].doc_timestamp);
    assert!(report.signatures[1].is_intact());

    let sha1 = const_oid::ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
    let weak = edit_cms(&stamped, 1, |s| {
        let mut infos: Vec<_> = s.signer_infos.0.iter().cloned().collect();
        infos[0].digest_alg.oid = sha1;
        s.signer_infos.0 = SetOfVec::try_from(infos).unwrap();
    });
    let report = inspect(&open(weak), &now()).unwrap();
    assert_eq!(
        report.signatures[1].status,
        vec![ValidityError::AlgorithmNotSupported]
    );
}
