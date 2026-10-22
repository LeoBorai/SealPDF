mod common;

use common::*;
use lopdf::{Object, StringFormat, dictionary};
use sealpdf_pdf::PdfDocument;

/// A signed field whose dictionary carries the optional entries.
fn signed_pdf() -> Vec<u8> {
    let (mut doc, ids) = base(1);
    let sig = sig_dict(&mut doc, &SigSpec::default());
    let dict = doc.get_object_mut(sig).unwrap().as_dict_mut().unwrap();
    dict.set(
        "Contents",
        Object::String(vec![0x30, 0x03, 1, 2, 3, 0, 0], StringFormat::Hexadecimal),
    );
    dict.set("M", text("D:20260102030405+00'00'"));
    dict.set("Name", text("Jane Doe"));
    dict.set("Reason", text("I approve"));
    dict.set("Location", text("Madrid"));
    add_sig_field(&mut doc, ids[0], "Sig1", [10, 10, 100, 50], Some(sig));
    save(&mut doc)
}

#[test]
fn reads_the_signature_dictionary_entries() {
    let pdf = PdfDocument::open(signed_pdf(), None).unwrap();
    let value = pdf.signatures()[0].value.clone().unwrap();
    assert_eq!(value.contents, Some(vec![0x30, 0x03, 1, 2, 3, 0, 0]));
    assert_eq!(
        value.signing_time.as_deref(),
        Some("D:20260102030405+00'00'")
    );
    assert_eq!(value.name.as_deref(), Some("Jane Doe"));
    assert_eq!(value.reason.as_deref(), Some("I approve"));
    assert_eq!(value.location.as_deref(), Some("Madrid"));
}

#[test]
fn missing_entries_are_none() {
    let (mut doc, ids) = base(1);
    let sig = sig_dict(&mut doc, &SigSpec::default());
    add_sig_field(&mut doc, ids[0], "Sig1", [10, 10, 100, 50], Some(sig));
    let pdf = PdfDocument::open(save(&mut doc), None).unwrap();
    let value = pdf.signatures()[0].value.clone().unwrap();
    assert_eq!(value.signing_time, None);
    assert_eq!(value.name, None);
    assert_eq!(value.reason, None);
    assert_eq!(value.location, None);
}

#[test]
fn has_dss_follows_the_catalog() {
    let bytes = signed_pdf();
    assert!(!PdfDocument::open(bytes.clone(), None).unwrap().has_dss());

    let with_dss = append_revision(&bytes, |inc| {
        let catalog = inc
            .get_prev_documents()
            .trailer
            .get(b"Root")
            .unwrap()
            .as_reference()
            .unwrap();
        inc.opt_clone_object_to_new_document(catalog).unwrap();
        let dss = inc
            .new_document
            .add_object(dictionary! { "Certs" => Vec::<Object>::new() });
        inc.new_document
            .get_object_mut(catalog)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("DSS", dss);
    });
    let pdf = PdfDocument::open(with_dss, None).unwrap();
    assert!(pdf.has_dss());
    assert_eq!(pdf.revisions().len(), 2);
}
