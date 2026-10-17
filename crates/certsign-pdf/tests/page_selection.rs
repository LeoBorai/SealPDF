mod common;

use certsign_core::{ErrorCode, Page as PageSel};
use certsign_pdf::{
    AppearanceSpec, AttachedField, FieldTarget, FontSpec, IncrementalWriter, PdfDocument,
    add_appearance, attach_signature, set_widget_appearance,
};
use common::*;
use lopdf::{Object, dictionary};

fn sig_entries() -> lopdf::Dictionary {
    dictionary! { "Type" => "Sig", "Filter" => "Adobe.PPKLite", "SubFilter" => "adbe.pkcs7.detached" }
}

fn place(
    bytes: &[u8],
    page: PageSel,
    rect: Option<[f32; 4]>,
) -> certsign_core::Result<(Vec<u8>, AttachedField)> {
    let pdf = PdfDocument::open(bytes.to_vec(), None)?;
    let mut w = IncrementalWriter::new(&pdf)?;
    let sig = w.add_signature(sig_entries(), 128)?;
    let field = attach_signature(&mut w, &FieldTarget::New { page, rect }, sig)?;
    let out = w.finish_signature()?.embed(&[0x30, 0])?;
    Ok((out, field))
}

/// `pages` pages of 595 x 842 points.
fn doc(pages: usize, modern: bool) -> Vec<u8> {
    let (mut d, _) = base(pages);
    if modern {
        save_modern(&mut d)
    } else {
        save(&mut d)
    }
}

const RECT: Option<[f32; 4]> = Some([50.0, 50.0, 250.0, 120.0]);

fn code(e: certsign_core::Error) -> Option<ErrorCode> {
    e.code()
}

// ---- which page

#[test]
fn explicit_page_number() {
    for n in 1..=3 {
        let (out, field) = place(&doc(3, false), PageSel::Number(n), RECT).unwrap();
        assert_eq!(field.page, Some(n));
        assert_eq!(
            PdfDocument::open(out, None).unwrap().signatures()[0].page,
            Some(n)
        );
    }
}

#[test]
fn last_page() {
    // Matches the spec scenario: a rectangle and `visible.page = "last"`.
    for modern in [false, true] {
        let (out, field) = place(&doc(3, modern), PageSel::Last, RECT).unwrap();
        assert_eq!(field.page, Some(3));
        let pdf = PdfDocument::open(out, None).unwrap();
        let sig = &pdf.signatures()[0];
        assert_eq!((sig.page, sig.rect), (Some(3), RECT));
        assert_eq!(pdf.pages().len(), 3, "no page added");
    }
}

#[test]
fn page_out_of_range() {
    for page in [PageSel::Number(0), PageSel::Number(4)] {
        let err = place(&doc(3, false), page, RECT).unwrap_err();
        assert_eq!(
            code(err),
            Some(ErrorCode::INVALID_SIGNATURE_PAGE),
            "{page:?}"
        );
    }
}

#[test]
fn append_adds_a_blank_page_sized_like_page_one() {
    for modern in [false, true] {
        let original = doc(2, modern);
        let (out, field) = place(&original, PageSel::Append, RECT).unwrap();
        assert_eq!(out[..original.len()], original[..]);
        assert_eq!(field.page, Some(3));

        let pdf = PdfDocument::open(out, None).unwrap();
        assert_eq!(pdf.pages().len(), 3);
        // Original pages keep their order and ids; the new one is last.
        let before = PdfDocument::open(original, None).unwrap();
        assert_eq!(pdf.pages()[0].id, before.pages()[0].id);
        assert_eq!(pdf.pages()[1].id, before.pages()[1].id);
        let new_page = &pdf.pages()[2];
        assert_eq!(new_page.media_box, [0.0, 0.0, 595.0, 842.0]);
        assert_eq!(new_page.rotation, 0);

        // The tree root counts the new page, and the signature sits on it.
        let root = pdf
            .document()
            .catalog()
            .unwrap()
            .get(b"Pages")
            .unwrap()
            .as_reference()
            .unwrap();
        let root = pdf.document().get_dictionary(root).unwrap();
        assert_eq!(root.get(b"Count").unwrap().as_i64().unwrap(), 3);
        assert_eq!(root.get(b"Kids").unwrap().as_array().unwrap().len(), 3);
        let sig = &pdf.signatures()[0];
        assert_eq!(sig.page, Some(3));
        assert_eq!(sig.rect, RECT);
        let annots = pdf
            .document()
            .get_dictionary(new_page.id)
            .unwrap()
            .get(b"Annots")
            .unwrap()
            .as_array()
            .unwrap()
            .len();
        assert_eq!(annots, 1);
    }
}

#[test]
fn append_copies_the_size_of_a_rotated_first_page() {
    // Page one is 400 x 300 rotated by 90: the new page is 300 x 400, unrotated.
    let (mut d, ids) = base(1);
    {
        let page = d.get_object_mut(ids[0]).unwrap().as_dict_mut().unwrap();
        page.set("MediaBox", vec![int(0), int(0), int(400), int(300)]);
        page.set("Rotate", int(90));
    }
    let (out, _) = place(&save(&mut d), PageSel::Append, RECT).unwrap();
    let pdf = PdfDocument::open(out, None).unwrap();
    assert_eq!(pdf.pages()[1].media_box, [0.0, 0.0, 300.0, 400.0]);
}

#[test]
fn append_twice() {
    let (one, _) = place(&doc(1, false), PageSel::Append, RECT).unwrap();
    let (two, f) = place(&one, PageSel::Append, RECT).unwrap();
    assert_eq!(f.page, Some(3));
    let pdf = PdfDocument::open(two, None).unwrap();
    assert_eq!(pdf.pages().len(), 3);
    assert_eq!(pdf.signatures().len(), 2);
}

#[test]
fn append_with_an_invalid_rectangle_changes_nothing() {
    let err = place(&doc(1, false), PageSel::Append, Some([1.0, 1.0, 1.0, 50.0])).unwrap_err();
    assert_eq!(code(err), Some(ErrorCode::INVALID_SIGNATURE_POSITION));
}

// ---- the rectangle

#[test]
fn zero_area_rectangle_is_invalid() {
    for rect in [
        [10.0, 10.0, 10.0, 50.0],
        [10.0, 10.0, 90.0, 10.0],
        [0.0, 0.0, 0.0, 0.0],
        [f32::NAN, 0.0, 10.0, 10.0],
    ] {
        let err = place(&doc(1, false), PageSel::Number(1), Some(rect)).unwrap_err();
        assert_eq!(
            code(err),
            Some(ErrorCode::INVALID_SIGNATURE_POSITION),
            "{rect:?}"
        );
    }
}

#[test]
fn rectangle_fully_outside_the_page_is_invalid() {
    for rect in [
        [600.0, 10.0, 700.0, 50.0], // right of the page
        [595.0, 10.0, 700.0, 50.0], // starts on the right edge
        [10.0, 842.0, 90.0, 900.0], // above the page
        [-100.0, 10.0, 0.0, 50.0],  // left of the page
        [10.0, -50.0, 90.0, 0.0],   // below the page
    ] {
        let err = place(&doc(1, false), PageSel::Number(1), Some(rect)).unwrap_err();
        assert_eq!(
            code(err),
            Some(ErrorCode::INVALID_SIGNATURE_POSITION),
            "{rect:?}"
        );
    }
}

#[test]
fn rectangle_overhanging_the_page_is_clipped() {
    let (out, field) = place(
        &doc(1, false),
        PageSel::Number(1),
        Some([500.0, 800.0, 700.0, 900.0]),
    )
    .unwrap();
    assert_eq!(field.rect, [500.0, 800.0, 595.0, 842.0]);
    assert_eq!(
        PdfDocument::open(out, None).unwrap().signatures()[0].rect,
        Some([500.0, 800.0, 595.0, 842.0])
    );
    // Bleeding off the left or bottom edge stays as given: only top and right are clipped.
    let (_, field) = place(
        &doc(1, false),
        PageSel::Number(1),
        Some([-10.0, -10.0, 50.0, 50.0]),
    )
    .unwrap();
    assert_eq!(field.rect, [-10.0, -10.0, 50.0, 50.0]);
}

#[test]
fn reversed_corners_are_normalized() {
    let (_, field) = place(
        &doc(1, false),
        PageSel::Number(1),
        Some([250.0, 120.0, 50.0, 50.0]),
    )
    .unwrap();
    assert_eq!(field.rect, [50.0, 50.0, 250.0, 120.0]);
}

#[test]
fn rotated_page_swaps_width_and_height() {
    // 595 x 842 rotated by 90 is 842 wide and 595 high.
    let (mut d, ids) = base(1);
    d.get_object_mut(ids[0])
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Rotate", int(90));
    let bytes = save(&mut d);
    assert!(place(&bytes, PageSel::Number(1), Some([700.0, 10.0, 800.0, 50.0])).is_ok());
    let err = place(&bytes, PageSel::Number(1), Some([10.0, 600.0, 90.0, 700.0])).unwrap_err();
    assert_eq!(code(err), Some(ErrorCode::INVALID_SIGNATURE_POSITION));
}

#[test]
fn crop_box_defines_the_page() {
    let (mut d, ids) = base(1);
    d.get_object_mut(ids[0])
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("CropBox", vec![int(100), int(100), int(300), int(300)]);
    let bytes = save(&mut d);
    assert!(
        place(
            &bytes,
            PageSel::Number(1),
            Some([150.0, 150.0, 250.0, 250.0])
        )
        .is_ok()
    );
    let err = place(
        &bytes,
        PageSel::Number(1),
        Some([400.0, 400.0, 500.0, 500.0]),
    )
    .unwrap_err();
    assert_eq!(code(err), Some(ErrorCode::INVALID_SIGNATURE_POSITION));
    let err = place(&bytes, PageSel::Number(1), Some([10.0, 10.0, 90.0, 90.0])).unwrap_err();
    assert_eq!(code(err), Some(ErrorCode::INVALID_SIGNATURE_POSITION));
}

#[test]
fn invisible_signature_needs_no_rectangle_check() {
    let (_, field) = place(&doc(1, false), PageSel::Last, None).unwrap();
    assert!(!field.is_visible());
}

// ---- the scenario end to end

#[test]
fn visible_signature_on_last_page_draws_the_configured_text() {
    let bytes = doc(2, false);
    let pdf = PdfDocument::open(bytes, None).unwrap();
    let mut w = IncrementalWriter::new(&pdf).unwrap();
    let sig = w.add_signature(sig_entries(), 128).unwrap();
    let field = attach_signature(
        &mut w,
        &FieldTarget::New {
            page: PageSel::Last,
            rect: RECT,
        },
        sig,
    )
    .unwrap();
    let [llx, lly, urx, ury] = field.rect;
    let form = add_appearance(
        &mut w,
        &AppearanceSpec {
            width: urx - llx,
            height: ury - lly,
            text: Some("Firmado"),
            font: FontSpec::default(),
            image: None,
            rotation: 0,
        },
    )
    .unwrap();
    set_widget_appearance(&mut w, field.widget_id, form).unwrap();
    let out = w.finish_signature().unwrap().embed(&[0x30, 0]).unwrap();

    let pdf = PdfDocument::open(out, None).unwrap();
    let widget = pdf.document().get_dictionary(field.widget_id).unwrap();
    let rect: Vec<f32> = widget
        .get(b"Rect")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o.as_float().unwrap())
        .collect();
    assert_eq!(rect, [50.0, 50.0, 250.0, 120.0]);
    assert_eq!(
        widget.get(b"P").unwrap().as_reference().unwrap(),
        pdf.page(2).unwrap().id
    );
    let ap = widget
        .get(b"AP")
        .unwrap()
        .as_dict()
        .unwrap()
        .get(b"N")
        .unwrap()
        .as_reference()
        .unwrap();
    let stream = pdf.document().get_object(ap).unwrap().as_stream().unwrap();
    assert!(String::from_utf8_lossy(&stream.content).contains("(Firmado) Tj"));
    assert!(matches!(widget.get(b"Subtype").unwrap(), Object::Name(n) if n == b"Widget"));
}

/// Writes samples for inspection with other tools when `CERTSIGN_KEEP_DIR` is set.
#[test]
fn keep_samples_for_inspection() {
    let Ok(dir) = std::env::var("CERTSIGN_KEEP_DIR") else {
        return;
    };
    let dir = std::path::Path::new(&dir);
    for (name, modern) in [
        ("page-append-classic.pdf", false),
        ("page-append-xref-stream.pdf", true),
    ] {
        let (out, _) = place(&doc(2, modern), PageSel::Append, RECT).unwrap();
        std::fs::write(dir.join(name), out).unwrap();
    }
}
