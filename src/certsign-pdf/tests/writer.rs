mod common;

use certsign_core::Error;
use certsign_pdf::{IncrementalWriter, PdfDocument, PreparedSignature};
use common::*;
use lopdf::{Object, dictionary};
use sha2::{Digest, Sha256};

fn sig_entries() -> lopdf::Dictionary {
    dictionary! {
        "Type" => "Sig",
        "Filter" => "Adobe.PPKLite",
        "SubFilter" => "adbe.pkcs7.detached",
    }
}

fn hash(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// Checks the `/ByteRange` invariants straight from the bytes, without any PDF parser.
fn assert_byte_range_intact(bytes: &[u8], range: [usize; 4]) {
    let [a0, a1, b0, b1] = range;
    assert_eq!(a0, 0);
    assert!(a1 < b0);
    assert_eq!(b0 + b1, bytes.len(), "second range reaches the end of file");
    assert_eq!(bytes[a1], b'<', "gap starts at the hex string");
    assert_eq!(bytes[b0 - 1], b'>', "gap ends at the hex string");
    assert!(
        bytes[a1 + 1..b0 - 1].iter().all(u8::is_ascii_hexdigit),
        "gap holds only hex digits"
    );
    let text = String::from_utf8_lossy(bytes);
    let declared = format!("/ByteRange [0 {:<10} {:<10} {:<10}]", a1, b0, b1);
    assert!(
        text.contains(&declared),
        "declared ByteRange matches: {declared}"
    );
}

/// A page-one document with an unsigned field `Sig1`, returned with the field's widget id.
fn with_empty_field(xref_stream: bool) -> (Vec<u8>, lopdf::ObjectId) {
    let (mut doc, ids) = base(1);
    let widget = add_sig_field(&mut doc, ids[0], "Sig1", [50, 50, 250, 120], None);
    let bytes = if xref_stream {
        save_modern(&mut doc)
    } else {
        save(&mut doc)
    };
    (bytes, widget)
}

fn sign_field(bytes: &[u8], widget: lopdf::ObjectId, reserved: usize) -> PreparedSignature {
    let pdf = PdfDocument::open(bytes.to_vec(), None).unwrap();
    let mut w = IncrementalWriter::new(&pdf).unwrap();
    let sig = w.add_signature(sig_entries(), reserved).unwrap();
    w.modify(widget)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("V", sig);
    w.finish_signature().unwrap()
}

#[test]
fn plain_update_preserves_original_and_chains_trailer() {
    let (mut doc, _) = base(1);
    let original = save(&mut doc);
    let pdf = PdfDocument::open(original.clone(), None).unwrap();

    let mut w = IncrementalWriter::new(&pdf).unwrap();
    let extra = w.add_object(dictionary! { "Marker" => text("hello") });
    let catalog = pdf
        .document()
        .trailer
        .get(b"Root")
        .unwrap()
        .as_reference()
        .unwrap();
    w.modify(catalog)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Extra", extra);
    let out = w.finish().unwrap();

    assert_eq!(
        out[..original.len()],
        original[..],
        "original bytes preserved"
    );
    let updated = PdfDocument::open(out.clone(), None).unwrap();
    assert_eq!(updated.revisions().len(), 2);
    assert!(!updated.revisions()[1].xref_stream);
    assert_eq!(
        updated.revisions()[1].end,
        out.len() - 1,
        "ends at %%EOF plus a line end"
    );

    let doc = updated.document();
    let cat = doc.get_dictionary(catalog).unwrap();
    assert_eq!(cat.get(b"Extra").unwrap().as_reference().unwrap(), extra);
    assert!(cat.has(b"Pages"), "unchanged catalog entries survive");
    assert_eq!(
        doc.get_dictionary(extra)
            .unwrap()
            .get(b"Marker")
            .unwrap()
            .as_str()
            .unwrap(),
        b"hello"
    );

    // /ID: first element kept, second renewed.
    let id = |d: &lopdf::Document| {
        d.trailer
            .get(b"ID")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_str().unwrap().to_vec())
            .collect::<Vec<_>>()
    };
    let (before, after) = (id(pdf.document()), id(doc));
    assert_eq!(before[0], after[0]);
    assert_ne!(before[1], after[1]);

    // /Size covers the new object.
    assert!(doc.trailer.get(b"Size").unwrap().as_i64().unwrap() > i64::from(extra.0));
}

#[test]
fn output_is_deterministic() {
    let (bytes, widget) = with_empty_field(false);
    let a = sign_field(&bytes, widget, 1000).embed(&[1, 2, 3]).unwrap();
    let b = sign_field(&bytes, widget, 1000).embed(&[1, 2, 3]).unwrap();
    assert_eq!(a, b);
}

#[test]
fn xref_style_matches_previous_revision() {
    for xref_stream in [false, true] {
        let (bytes, widget) = with_empty_field(xref_stream);
        let first = PdfDocument::open(bytes.clone(), None).unwrap();
        assert_eq!(first.revisions().last().unwrap().xref_stream, xref_stream);

        let out = sign_field(&bytes, widget, 1000).embed(&[0xAB; 8]).unwrap();
        let second = PdfDocument::open(out, None).unwrap();
        assert_eq!(second.revisions().len(), 2, "stream={xref_stream}");
        assert_eq!(
            second.revisions().last().unwrap().xref_stream,
            xref_stream,
            "new revision uses the same xref style"
        );
        assert_eq!(second.signatures().len(), 1);
    }
}

#[test]
fn xref_chain_survives_a_third_update() {
    for xref_stream in [false, true] {
        let (bytes, widget) = with_empty_field(xref_stream);
        let one = sign_field(&bytes, widget, 500).embed(&[1]).unwrap();
        let pdf = PdfDocument::open(one, None).unwrap();
        let mut w = IncrementalWriter::new(&pdf).unwrap();
        let extra = w.add_object(dictionary! { "N" => 3 });
        let out = w.finish().unwrap();
        let pdf = PdfDocument::open(out, None).unwrap();
        assert_eq!(pdf.revisions().len(), 3, "stream={xref_stream}");
        assert!(pdf.document().get_object(extra).is_ok());
        assert_eq!(pdf.signatures().len(), 1, "earlier objects still resolve");
    }
}

#[test]
fn dummy_signature_has_intact_byte_range() {
    for xref_stream in [false, true] {
        let (bytes, widget) = with_empty_field(xref_stream);
        let prepared = sign_field(&bytes, widget, 27_000);

        assert_eq!(prepared.capacity(), 27_000);
        let range = prepared.byte_range();
        let signed_before = hash(&prepared.signed_parts());

        let cms = vec![0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB];
        let out = prepared.embed(&cms).unwrap();

        assert_eq!(out[..bytes.len()], bytes[..], "original bytes preserved");
        assert_byte_range_intact(&out, range);

        // The bytes that get signed do not change when the signature is embedded.
        let signed_after = hash(&[&out[..range[1]], &out[range[2]..]]);
        assert_eq!(signed_before, signed_after);

        // Embedded value, zero padded to the reserved size.
        let hex = std::str::from_utf8(&out[range[1] + 1..range[2] - 1]).unwrap();
        assert_eq!(hex.len(), 2 * 27_000);
        assert!(hex.starts_with("30820100AABB"));
        assert!(hex[12..].bytes().all(|b| b == b'0'));

        // A parser agrees.
        let pdf = PdfDocument::open(out.clone(), None).unwrap();
        let sigs = pdf.signatures();
        assert_eq!(sigs.len(), 1);
        let value = sigs[0].value.as_ref().unwrap();
        assert_eq!(
            value.byte_range.as_deref(),
            Some(&[0, range[1] as i64, range[2] as i64, range[3] as i64][..])
        );
        assert_eq!(value.sub_filter.as_deref(), Some("adbe.pkcs7.detached"));
        assert_eq!(sigs[0].name, "Sig1");
        assert_eq!(pdf.revisions().len(), 2);
    }
}

#[test]
fn signature_too_large_is_an_error() {
    let (bytes, widget) = with_empty_field(false);
    let prepared = sign_field(&bytes, widget, 16);
    let err = prepared.embed(&[0; 17]).unwrap_err();
    assert!(
        matches!(
            err,
            Error::SignatureTooLarge {
                needed: 17,
                reserved: 16
            }
        ),
        "{err}"
    );
    // Exactly the capacity fits.
    let prepared = sign_field(&bytes, widget, 16);
    assert!(prepared.embed(&[0xFF; 16]).is_ok());
}

#[test]
fn second_signature_keeps_first_range_valid() {
    let (bytes, widget) = with_empty_field(false);
    let first = sign_field(&bytes, widget, 2000);
    let r1 = first.byte_range();
    let out1 = first.embed(&[7; 40]).unwrap();
    let signed1 = hash(&[&out1[..r1[1]], &out1[r1[2]..]]);

    // A second signature in a new field of the signed file.
    let pdf = PdfDocument::open(out1.clone(), None).unwrap();
    let mut w = IncrementalWriter::new(&pdf).unwrap();
    let sig2 = w.add_signature(sig_entries(), 2000).unwrap();
    let page = pdf.page(1).unwrap().id;
    let widget2 = w.add_object(dictionary! {
        "Type" => "Annot", "Subtype" => "Widget", "FT" => "Sig", "T" => text("Sig2"),
        "F" => 132, "P" => page, "V" => sig2,
        "Rect" => vec![int(0), int(0), int(0), int(0)],
    });
    let catalog = pdf
        .document()
        .trailer
        .get(b"Root")
        .unwrap()
        .as_reference()
        .unwrap();
    let form = pdf
        .document()
        .get_dictionary(catalog)
        .unwrap()
        .get(b"AcroForm")
        .unwrap()
        .as_reference()
        .unwrap();
    match w
        .modify(form)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .get_mut(b"Fields")
        .unwrap()
    {
        Object::Array(a) => a.push(widget2.into()),
        other => panic!("Fields is {other:?}"),
    }
    let prepared = w.finish_signature().unwrap();
    let r2 = prepared.byte_range();
    let out2 = prepared.embed(&[9; 40]).unwrap();

    // The first signature's covered bytes are untouched by the second update.
    assert_eq!(out2[..out1.len()], out1[..]);
    let signed1_again = hash(&[&out2[..r1[1]], &out2[r1[2]..r1[2] + r1[3]]]);
    assert_eq!(signed1, signed1_again);
    assert_byte_range_intact(&out2, r2);
    // The second signature covers the first one completely.
    assert!(r2[2] > out1.len() - 1);

    let pdf = PdfDocument::open(out2, None).unwrap();
    assert_eq!(pdf.revisions().len(), 3);
    let names: Vec<_> = pdf.signatures().into_iter().map(|s| s.name).collect();
    assert_eq!(names, ["Sig1", "Sig2"]);
}

#[test]
fn file_without_trailing_newline() {
    let (mut doc, _) = base(1);
    let original = save(&mut doc);
    // lopdf ends the file at `%%EOF`, with no line end.
    assert!(original.ends_with(b"%%EOF"));
    let pdf = PdfDocument::open(original.clone(), None).unwrap();
    let w = IncrementalWriter::new(&pdf).unwrap();
    let out = w.finish().unwrap();
    assert_eq!(out[..original.len()], original[..]);
    // The update starts on its own line.
    assert_eq!(out[original.len()], b'\n');
    assert_eq!(PdfDocument::open(out, None).unwrap().revisions().len(), 2);
}

#[test]
fn rejects_misuse() {
    let (mut doc, _) = base(1);
    let pdf = PdfDocument::open(save(&mut doc), None).unwrap();

    let mut w = IncrementalWriter::new(&pdf).unwrap();
    w.add_signature(sig_entries(), 10).unwrap();
    assert!(
        w.add_signature(sig_entries(), 10).is_err(),
        "one signature per update"
    );

    let mut w = IncrementalWriter::new(&pdf).unwrap();
    w.add_signature(sig_entries(), 10).unwrap();
    assert!(w.finish().is_err(), "placeholder needs finish_signature");

    let w = IncrementalWriter::new(&pdf).unwrap();
    assert!(w.finish_signature().is_err(), "no placeholder");

    // Garbage with a header but no valid trailer cannot be appended to.
    let broken = PdfDocument::open(
        b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>".to_vec(),
        None,
    );
    if let Ok(broken) = broken {
        assert!(IncrementalWriter::new(&broken).is_err());
    }
}
