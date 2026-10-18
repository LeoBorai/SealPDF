mod common;

use common::*;
use lopdf::{
    EncryptionState, EncryptionVersion, Object, Permissions, dictionary,
    encryption::crypt_filters::{Aes128CryptFilter, CryptFilter},
};
use sealpdf_core::{Error, ErrorCode};
use sealpdf_pdf::PdfDocument;
use std::{collections::BTreeMap, sync::Arc};

fn code(e: Error) -> ErrorCode {
    e.code().expect("error has a code")
}

#[test]
fn plain_pdf() {
    let (mut doc, ids) = base(2);
    doc.get_object_mut(ids[1])
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Rotate", int(-90));
    let pdf = PdfDocument::open(save(&mut doc), None).unwrap();

    assert!(!pdf.is_encrypted());
    assert_eq!(pdf.revisions().len(), 1);
    assert_eq!(pdf.revisions()[0].end, pdf.bytes().len());
    assert_eq!(pdf.pages().len(), 2);
    assert!(pdf.acroform().is_none());
    assert!(pdf.signature_fields().is_empty());
    assert_eq!(pdf.certification_level(), None);

    let p1 = pdf.page(1).unwrap();
    assert_eq!(p1.media_box, [0.0, 0.0, 595.0, 842.0]); // inherited
    assert_eq!(p1.crop_box, p1.media_box);
    assert_eq!(p1.rotation, 0);
    assert_eq!(pdf.page(2).unwrap().rotation, 270);
    assert!(pdf.page(3).is_none());
}

#[test]
fn xref_stream_and_object_streams() {
    let (mut doc, _) = base(3);
    let pdf = PdfDocument::open(save_modern(&mut doc), None).unwrap();
    assert_eq!(pdf.revisions().len(), 1);
    assert_eq!(pdf.pages().len(), 3);
}

#[test]
fn rejects_non_pdf() {
    let err = PdfDocument::open(b"hello world".to_vec(), None)
        .err()
        .unwrap();
    assert!(matches!(err, Error::InvalidPdf(_)), "{err}");
}

#[test]
fn unsigned_field() {
    let (mut doc, ids) = base(2);
    add_sig_field(&mut doc, ids[1], "Sig1", [50, 50, 250, 120], None);
    let pdf = PdfDocument::open(save(&mut doc), None).unwrap();

    let form = pdf.acroform().unwrap();
    assert_eq!(form.sig_flags, 3);
    let fields = pdf.signature_fields();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].name, "Sig1");
    assert!(!fields[0].is_signed());
    assert_eq!(fields[0].page, Some(2));
    assert_eq!(fields[0].rect, Some([50.0, 50.0, 250.0, 120.0]));
    assert!(pdf.signatures().is_empty());
}

#[test]
fn counts_revisions_across_incremental_updates() {
    let (mut doc, ids) = base(1);
    let sig = sig_dict(&mut doc, &SigSpec::default());
    add_sig_field(&mut doc, ids[0], "First", [10, 10, 100, 50], Some(sig));
    let one = save(&mut doc);
    assert_eq!(
        PdfDocument::open(one.clone(), None)
            .unwrap()
            .revisions()
            .len(),
        1
    );

    // Second revision: add another signed field.
    let two = append_revision(&one, |inc| {
        let prev = inc.get_prev_documents();
        let page = *prev.get_pages().get(&1).unwrap();
        let catalog = prev.trailer.get(b"Root").unwrap().as_reference().unwrap();
        let form = prev
            .get_dictionary(catalog)
            .unwrap()
            .get(b"AcroForm")
            .unwrap()
            .as_reference()
            .unwrap();
        inc.opt_clone_object_to_new_document(page).unwrap();
        inc.opt_clone_object_to_new_document(form).unwrap();

        let nd = &mut inc.new_document;
        let sig2 = sig_dict(nd, &SigSpec::default());
        let widget = nd.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Widget", "FT" => "Sig",
            "T" => text("Second"), "F" => 132, "P" => page, "V" => sig2,
            "Rect" => vec![int(10), int(60), int(100), int(100)],
        });
        nd.get_object_mut(page)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .get_mut(b"Annots")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(widget.into());
        nd.get_object_mut(form)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .get_mut(b"Fields")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(widget.into());
    });
    assert_eq!(two[..one.len()], one[..], "original bytes preserved");

    let pdf = PdfDocument::open(two.clone(), None).unwrap();
    assert_eq!(pdf.revisions().len(), 2);
    assert_eq!(pdf.revisions()[0].end, one.len());
    assert_eq!(pdf.revisions()[1].end, two.len());
    let sigs = pdf.signatures();
    assert_eq!(
        sigs.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        ["First", "Second"]
    );
    assert_eq!(
        sigs[0].value.as_ref().unwrap().byte_range,
        Some(vec![0, 10, 20, 30])
    );
    assert_eq!(
        sigs[0].value.as_ref().unwrap().sub_filter.as_deref(),
        Some("adbe.pkcs7.detached")
    );
}

#[test]
fn document_timestamps_are_not_signatures() {
    let (mut doc, ids) = base(1);
    let sig = sig_dict(&mut doc, &SigSpec::default());
    add_sig_field(&mut doc, ids[0], "Sig", [10, 10, 100, 50], Some(sig));
    let ts = sig_dict(
        &mut doc,
        &SigSpec {
            sub_filter: "ETSI.RFC3161",
            doc_timestamp: true,
            docmdp: None,
        },
    );
    add_sig_field(&mut doc, ids[0], "Timestamp", [0, 0, 0, 0], Some(ts));
    let pdf = PdfDocument::open(save(&mut doc), None).unwrap();

    assert_eq!(pdf.signature_fields().len(), 2);
    assert_eq!(pdf.signatures().len(), 1);
    assert_eq!(pdf.signatures()[0].name, "Sig");
    assert_eq!(pdf.document_timestamps().len(), 1);
    assert_eq!(pdf.document_timestamps()[0].name, "Timestamp");
}

#[test]
fn certification_level() {
    for p in 1..=3 {
        let (mut doc, ids) = base(1);
        let sig = sig_dict(
            &mut doc,
            &SigSpec {
                docmdp: Some(p),
                ..Default::default()
            },
        );
        add_sig_field(&mut doc, ids[0], "Cert", [10, 10, 100, 50], Some(sig));
        let catalog = catalog_id(&doc);
        let perms = doc.add_object(dictionary! { "DocMDP" => sig });
        doc.get_object_mut(catalog)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("Perms", perms);
        let pdf = PdfDocument::open(save(&mut doc), None).unwrap();
        assert_eq!(pdf.certification_level(), Some(p as u8));
        assert_eq!(
            pdf.signatures()[0].value.as_ref().unwrap().docmdp,
            Some(p as u8)
        );
    }
}

#[test]
fn hierarchical_field_names() {
    let (mut doc, ids) = base(1);
    let widget = doc.add_object(dictionary! {
        "Type" => "Annot", "Subtype" => "Widget", "T" => text("sig"), "P" => ids[0],
        "Rect" => vec![int(1), int(2), int(3), int(4)],
    });
    let parent = doc.add_object(dictionary! {
        "T" => text("group"), "FT" => "Sig", "Kids" => vec![Object::Reference(widget)],
    });
    doc.get_object_mut(widget)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Parent", parent);
    let form = doc.add_object(dictionary! { "Fields" => vec![Object::Reference(parent)] });
    let catalog = catalog_id(&doc);
    doc.get_object_mut(catalog)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("AcroForm", form);
    let pdf = PdfDocument::open(save(&mut doc), None).unwrap();

    let fields = pdf.signature_fields();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].name, "group.sig");
    assert_eq!(fields[0].rect, Some([1.0, 2.0, 3.0, 4.0]));
}

fn encrypted(version: u8, user: &str) -> Vec<u8> {
    let (mut doc, _) = base(2);
    let perms = Permissions::PRINTABLE | Permissions::COPYABLE;
    let state = match version {
        1 => EncryptionState::try_from(EncryptionVersion::V1 {
            document: &doc,
            owner_password: "owner",
            user_password: user,
            permissions: perms,
        }),
        2 => EncryptionState::try_from(EncryptionVersion::V2 {
            document: &doc,
            owner_password: "owner",
            user_password: user,
            key_length: 128,
            permissions: perms,
        }),
        _ => {
            let filter: Arc<dyn CryptFilter> = Arc::new(Aes128CryptFilter);
            EncryptionState::try_from(EncryptionVersion::V4 {
                document: &doc,
                encrypt_metadata: true,
                crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), filter)]),
                stream_filter: b"StdCF".to_vec(),
                string_filter: b"StdCF".to_vec(),
                owner_password: "owner",
                user_password: user,
                permissions: perms,
            })
        }
    }
    .unwrap();
    doc.encrypt(&state).unwrap();
    save(&mut doc)
}

#[test]
fn password_protected_rc4_and_aes() {
    for (version, key_bits) in [(1, 40), (2, 128), (4, 128)] {
        let bytes = encrypted(version, "user");

        let err = PdfDocument::open(bytes.clone(), None).err().unwrap();
        assert_eq!(code(err), ErrorCode::PDF_PASSWORD_REQUIRED, "v{version}");

        let err = PdfDocument::open(bytes.clone(), Some("wrong"))
            .err()
            .unwrap();
        assert_eq!(code(err), ErrorCode::PDF_BAD_PASSWORD, "v{version}");

        for pw in ["user", "owner"] {
            let pdf = PdfDocument::open(bytes.clone(), Some(pw)).unwrap();
            assert!(pdf.is_encrypted(), "v{version}");
            assert_eq!(pdf.pages().len(), 2, "v{version} {pw}");
            let info = pdf.encryption().unwrap();
            assert_eq!(info.version, version as i64);
            if let Some(bits) = info.key_length {
                assert_eq!(bits, key_bits, "v{version}");
            }
        }
    }
}

#[test]
fn empty_user_password_opens_without_one() {
    let pdf = PdfDocument::open(encrypted(2, ""), None).unwrap();
    assert!(pdf.is_encrypted());
    assert_eq!(pdf.pages().len(), 2);
}
