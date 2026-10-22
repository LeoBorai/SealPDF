mod common;

use common::*;
use lopdf::{EncryptionState, EncryptionVersion, Permissions};
use sealpdf_core::Error;
use sealpdf_validate::inspect;
use serde_json::json;

#[test]
fn the_json_report_of_a_clean_signed_pdf() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("Ada Lovelace", None);
    let file = sign(&blank_pdf(1, false), &store(&pki, &leaf), "Ada Lovelace");

    let report = inspect(&open(file), &now()).unwrap();
    assert_eq!(
        serde_json::to_value(&report).unwrap(),
        json!({
            "version": 1,
            "revisions": 2,
            "signatures": [{
                "field": "Signature1",
                "page": 1,
                "sub_filter": "adbe.pkcs7.detached",
                "doc_timestamp": false,
                "signer": "Ada Lovelace",
                "signed_at": "2024-05-17T10:30:00Z",
                "reason": null,
                "location": null,
                "revision": 2,
                "status": [],
            }],
            "verdicts": [{ "verdict": "OK" }],
            "trust_checked": false,
        })
    );
}

#[test]
fn to_json_is_the_indented_form_of_the_report() {
    let report = inspect(&open(blank_pdf(1, false)), &now()).unwrap();
    let text = report.to_json();
    assert!(text.contains("\n  \"verdicts\""), "{text}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text).unwrap(),
        serde_json::to_value(&report).unwrap()
    );
}

#[test]
fn the_json_report_of_an_unsigned_pdf() {
    let report = inspect(&open(blank_pdf(1, false)), &now()).unwrap();
    assert_eq!(
        serde_json::to_value(&report).unwrap(),
        json!({
            "version": 1,
            "revisions": 1,
            "signatures": [],
            "verdicts": [{ "verdict": "KO", "error": "NO_SIGN" }],
            "trust_checked": false,
        })
    );
}

#[test]
fn errors_use_the_stable_identifiers() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("Alice", None);
    let file = sign(&blank_pdf(1, false), &store(&pki, &leaf), "Alice");
    let report = inspect(&open(file), &at(2100)).unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(
        value["signatures"][0]["status"],
        json!(["CERTIFICATE_EXPIRED"])
    );
    assert_eq!(
        value["verdicts"],
        json!([{ "verdict": "KO", "error": "CERTIFICATE_EXPIRED" }])
    );
}

#[test]
fn an_encrypted_pdf_is_refused() {
    let mut doc = lopdf::Document::load_mem(&blank_pdf(1, false)).unwrap();
    let state = EncryptionState::try_from(EncryptionVersion::V2 {
        document: &doc,
        owner_password: "owner",
        user_password: "",
        key_length: 128,
        permissions: Permissions::PRINTABLE,
    })
    .unwrap();
    doc.encrypt(&state).unwrap();
    doc.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();

    let pdf = open(bytes);
    assert!(pdf.is_encrypted());
    let err = inspect(&pdf, &now()).unwrap_err();
    assert!(matches!(err, Error::Refused(_)), "{err}");
    assert!(err.to_string().contains("encrypted"), "{err}");
}
