mod common;

use certsign_core::{Error, ErrorCode};
use certsign_pdf::{FieldTarget, IncrementalWriter, PdfDocument, attach_signature};
use common::*;
use lopdf::{Document, Object, ObjectId, dictionary};

fn sig_entries() -> lopdf::Dictionary {
    dictionary! { "Type" => "Sig", "Filter" => "Adobe.PPKLite", "SubFilter" => "adbe.pkcs7.detached" }
}

/// Signs `bytes` into `target` with a dummy signature; returns the file and the attached field.
fn sign(
    bytes: &[u8],
    target: FieldTarget<'_>,
) -> certsign_core::Result<(Vec<u8>, certsign_pdf::AttachedField)> {
    let pdf = PdfDocument::open(bytes.to_vec(), None)?;
    let mut w = IncrementalWriter::new(&pdf)?;
    let sig = w.add_signature(sig_entries(), 512)?;
    let field = attach_signature(&mut w, &target, sig)?;
    let out = w.finish_signature()?.embed(&[0x30, 0x03, 1, 2, 3])?;
    Ok((out, field))
}

fn new_on(page: u32, rect: Option<[f32; 4]>) -> FieldTarget<'static> {
    FieldTarget::New { page, rect }
}

fn plain(pages: usize, modern: bool) -> Vec<u8> {
    let (mut doc, _) = base(pages);
    if modern {
        save_modern(&mut doc)
    } else {
        save(&mut doc)
    }
}

#[test]
fn new_visible_field_without_acroform() {
    for modern in [false, true] {
        let original = plain(2, modern);
        let (out, attached) = sign(&original, new_on(2, Some([50.0, 60.0, 250.0, 120.0]))).unwrap();

        assert!(attached.created && attached.is_visible());
        assert_eq!(attached.name, "Signature1");
        assert_eq!(out[..original.len()], original[..]);

        let pdf = PdfDocument::open(out, None).unwrap();
        let form = pdf.acroform().expect("AcroForm created");
        assert_eq!(form.sig_flags, 3);

        let sigs = pdf.signatures();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].name, "Signature1");
        assert_eq!(sigs[0].page, Some(2));
        assert_eq!(sigs[0].rect, Some([50.0, 60.0, 250.0, 120.0]));

        // Page /Annots references the widget, and only page 2 got one.
        let page = |n: u32| {
            pdf.document()
                .get_dictionary(pdf.page(n).unwrap().id)
                .unwrap()
                .clone()
        };
        let annots = page(2).get(b"Annots").unwrap().as_array().unwrap().clone();
        assert_eq!(annots, vec![Object::Reference(attached.widget_id)]);
        assert!(!page(1).has(b"Annots"));

        // Widget dictionary shape.
        let widget = pdf.document().get_dictionary(attached.widget_id).unwrap();
        assert_eq!(
            widget.get(b"Subtype").unwrap().as_name().unwrap(),
            b"Widget"
        );
        assert_eq!(widget.get(b"FT").unwrap().as_name().unwrap(), b"Sig");
        assert_eq!(widget.get(b"F").unwrap().as_i64().unwrap(), 132);
        assert_eq!(
            widget.get(b"P").unwrap().as_reference().unwrap(),
            pdf.page(2).unwrap().id
        );
    }
}

#[test]
fn invisible_signature_has_zero_rect() {
    let (out, attached) = sign(&plain(1, false), new_on(1, None)).unwrap();
    assert!(!attached.is_visible());
    let pdf = PdfDocument::open(out, None).unwrap();
    assert_eq!(pdf.signatures()[0].rect, Some([0.0; 4]));
}

#[test]
fn field_names_do_not_collide() {
    let original = plain(1, false);
    let (one, a) = sign(&original, new_on(1, None)).unwrap();
    let (two, b) = sign(&one, new_on(1, None)).unwrap();
    assert_eq!(
        (a.name.as_str(), b.name.as_str()),
        ("Signature1", "Signature2")
    );
    let pdf = PdfDocument::open(two, None).unwrap();
    assert_eq!(pdf.revisions().len(), 3);
    assert_eq!(pdf.signatures().len(), 2);
    // Both widgets are still on the page.
    let annots = pdf
        .document()
        .get_dictionary(pdf.page(1).unwrap().id)
        .unwrap()
        .get(b"Annots")
        .unwrap()
        .as_array()
        .unwrap()
        .len();
    assert_eq!(annots, 2);
}

#[test]
fn name_skips_existing_non_signature_field() {
    let (mut doc, ids) = base(1);
    // A text field called Signature1 already exists.
    let text_field = doc.add_object(dictionary! {
        "Type" => "Annot", "Subtype" => "Widget", "FT" => "Tx", "T" => text("Signature1"),
        "Rect" => vec![int(0), int(0), int(10), int(10)], "P" => ids[0],
    });
    let form = doc.add_object(dictionary! { "Fields" => vec![Object::Reference(text_field)] });
    let cat = catalog_id(&doc);
    doc.get_object_mut(cat)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("AcroForm", form);
    let (_, attached) = sign(&save(&mut doc), new_on(1, None)).unwrap();
    assert_eq!(attached.name, "Signature2");
}

/// Existing AcroForm in each shape the format allows.
#[test]
fn appends_to_existing_form_variants() {
    // (a) indirect form, direct Fields, SigFlags missing.
    // (b) indirect form, indirect Fields array, SigFlags 1.
    // (c) direct form inside the catalog, direct Fields array, SigFlags 2.
    for variant in ['a', 'b', 'c'] {
        let (mut doc, ids) = base(1);
        let existing = doc.add_object(dictionary! {
            "Type" => "Annot", "Subtype" => "Widget", "FT" => "Tx", "T" => text("Other"),
            "Rect" => vec![int(0), int(0), int(10), int(10)], "P" => ids[0],
        });
        let cat = catalog_id(&doc);
        let fields: Object = match variant {
            'b' => Object::Reference(doc.add_object(vec![Object::Reference(existing)])),
            _ => vec![Object::Reference(existing)].into(),
        };
        let mut form = dictionary! { "Fields" => fields };
        match variant {
            'b' => form.set("SigFlags", 1),
            'c' => form.set("SigFlags", 2),
            _ => {}
        }
        let value: Object = if variant == 'c' {
            Object::Dictionary(form)
        } else {
            Object::Reference(doc.add_object(form))
        };
        doc.get_object_mut(cat)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("AcroForm", value);

        let original = save(&mut doc);
        let (out, attached) = sign(&original, new_on(1, Some([1.0, 1.0, 100.0, 50.0]))).unwrap();
        let pdf = PdfDocument::open(out, None).unwrap();
        assert_eq!(pdf.acroform().unwrap().sig_flags, 3, "variant {variant}");
        let names: Vec<_> = pdf.signature_fields().into_iter().map(|f| f.name).collect();
        assert_eq!(
            names,
            std::slice::from_ref(&attached.name),
            "variant {variant}"
        );

        // The pre-existing field is still in the form, ahead of the new one.
        let form = pdf.document().catalog().unwrap().get(b"AcroForm").unwrap();
        let form = pdf
            .document()
            .dereference(form)
            .unwrap()
            .1
            .as_dict()
            .unwrap();
        let list = pdf
            .document()
            .dereference(form.get(b"Fields").unwrap())
            .unwrap()
            .1
            .as_array()
            .unwrap();
        assert_eq!(
            list,
            &vec![
                Object::Reference(existing),
                Object::Reference(attached.widget_id)
            ],
            "variant {variant}"
        );
    }
}

#[test]
fn page_annots_as_indirect_array() {
    let (mut doc, ids) = base(1);
    let other = doc.add_object(dictionary! { "Type" => "Annot", "Subtype" => "Text", "Rect" => vec![int(0), int(0), int(5), int(5)] });
    let annots = doc.add_object(vec![Object::Reference(other)]);
    doc.get_object_mut(ids[0])
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Annots", annots);
    let (out, attached) = sign(&save(&mut doc), new_on(1, Some([1.0, 1.0, 9.0, 9.0]))).unwrap();
    let pdf = PdfDocument::open(out, None).unwrap();
    let arr = pdf
        .document()
        .get_object(annots)
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(
        arr,
        &vec![
            Object::Reference(other),
            Object::Reference(attached.widget_id)
        ]
    );
}

#[test]
fn rejects_page_out_of_range() {
    for page in [0, 2] {
        let err = sign(&plain(1, false), new_on(page, None)).unwrap_err();
        assert_eq!(
            err.code(),
            Some(ErrorCode::INVALID_SIGNATURE_PAGE),
            "page {page}"
        );
    }
}

fn with_empty_field(rect: [i64; 4], modern: bool) -> (Vec<u8>, ObjectId) {
    let (mut doc, ids) = base(2);
    let w = add_sig_field(&mut doc, ids[1], "Approval", rect, None);
    let bytes = if modern {
        save_modern(&mut doc)
    } else {
        save(&mut doc)
    };
    (bytes, w)
}

#[test]
fn fills_existing_empty_field() {
    for modern in [false, true] {
        let (original, widget) = with_empty_field([40, 40, 240, 100], modern);
        let before = PdfDocument::open(original.clone(), None).unwrap();
        let (out, attached) = sign(&original, FieldTarget::Existing { name: "Approval" }).unwrap();

        assert!(!attached.created);
        assert_eq!(attached.widget_id, widget);
        assert_eq!(attached.page, Some(2));
        assert_eq!(attached.rect, [40.0, 40.0, 240.0, 100.0]);

        let pdf = PdfDocument::open(out, None).unwrap();
        let fields = pdf.signature_fields();
        assert_eq!(fields.len(), 1, "no new field is created");
        assert_eq!(fields[0].name, "Approval");
        assert!(fields[0].is_signature());
        assert_eq!(
            fields[0].rect,
            Some([40.0, 40.0, 240.0, 100.0]),
            "rectangle kept"
        );
        assert_eq!(fields[0].page, Some(2));

        // Annotations and form lists are unchanged.
        let annots = |d: &Document, pdf: &PdfDocument| {
            d.get_dictionary(pdf.page(2).unwrap().id)
                .unwrap()
                .get(b"Annots")
                .unwrap()
                .clone()
        };
        assert_eq!(
            annots(before.document(), &before),
            annots(pdf.document(), &pdf)
        );
    }
}

#[test]
fn fills_field_whose_widget_is_a_kid() {
    let (mut doc, ids) = base(1);
    let widget = doc.add_object(dictionary! {
        "Type" => "Annot", "Subtype" => "Widget", "P" => ids[0],
        "Rect" => vec![int(5), int(6), int(105), int(46)],
    });
    let field = doc.add_object(dictionary! {
        "T" => text("Kidded"), "FT" => "Sig", "Kids" => vec![Object::Reference(widget)],
    });
    doc.get_object_mut(widget)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Parent", field);
    let form =
        doc.add_object(dictionary! { "Fields" => vec![Object::Reference(field)], "SigFlags" => 3 });
    let cat = catalog_id(&doc);
    doc.get_object_mut(cat)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("AcroForm", form);
    attach_to_page_annots(&mut doc, ids[0], widget);

    let (out, attached) = sign(&save(&mut doc), FieldTarget::Existing { name: "Kidded" }).unwrap();
    assert_eq!((attached.field_id, attached.widget_id), (field, widget));
    let pdf = PdfDocument::open(out, None).unwrap();
    assert!(
        pdf.document().get_dictionary(field).unwrap().has(b"V"),
        "/V lives on the field"
    );
    assert!(!pdf.document().get_dictionary(widget).unwrap().has(b"V"));
    assert_eq!(pdf.signatures().len(), 1);
    assert_eq!(pdf.signatures()[0].rect, Some([5.0, 6.0, 105.0, 46.0]));
}

fn attach_to_page_annots(doc: &mut Document, page: ObjectId, widget: ObjectId) {
    doc.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Annots", vec![Object::Reference(widget)]);
}

#[test]
fn existing_invisible_field() {
    let (original, _) = with_empty_field([0, 0, 0, 0], false);
    let (_, attached) = sign(&original, FieldTarget::Existing { name: "Approval" }).unwrap();
    assert!(!attached.is_visible());
}

#[test]
fn rejects_unusable_existing_fields() {
    let (original, _) = with_empty_field([40, 40, 240, 100], false);

    let err = sign(&original, FieldTarget::Existing { name: "Nope" }).unwrap_err();
    assert!(matches!(err, Error::SignatureField(_)), "{err}");

    // Fill it, then try to fill it again.
    let (signed, _) = sign(&original, FieldTarget::Existing { name: "Approval" }).unwrap();
    let err = sign(&signed, FieldTarget::Existing { name: "Approval" }).unwrap_err();
    assert!(err.to_string().contains("already signed"), "{err}");
}
