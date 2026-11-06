mod common;

use common::*;
use sealpdf_pdf::{PdfDocument, default_signature_box};

/// `pages` pages of 595 x 842 points; `tweak` edits the last page.
fn open(pages: usize, tweak: impl FnOnce(&mut lopdf::Dictionary)) -> PdfDocument {
    let (mut d, ids) = base(pages);
    tweak(
        d.get_object_mut(*ids.last().unwrap())
            .unwrap()
            .as_dict_mut()
            .unwrap(),
    );
    PdfDocument::open(save(&mut d), None).unwrap()
}

fn rotated(angle: i64) -> PdfDocument {
    open(1, |p| p.set("Rotate", int(angle)))
}

#[test]
fn a4_without_rotation() {
    let (page, rect) = default_signature_box(&open(1, |_| {})).unwrap();
    assert_eq!((page, rect), (1, [36.0, 36.0, 236.0, 86.0]));
}

#[test]
fn uses_the_last_page() {
    let (page, _) = default_signature_box(&open(3, |_| {})).unwrap();
    assert_eq!(page, 3);
}

#[test]
fn crop_box_offsets_the_box() {
    let doc = open(1, |p| {
        p.set("CropBox", vec![int(100), int(100), int(500), int(700)])
    });
    let (_, rect) = default_signature_box(&doc).unwrap();
    assert_eq!(rect, [136.0, 136.0, 336.0, 186.0]);
}

#[test]
fn rotated_pages_put_the_box_at_the_displayed_lower_left() {
    // The displayed lower-left corner of a 595 x 842 page is, in user space, the top-left
    // corner at 90 degrees, the top-right at 180 and the bottom-right at 270.
    let cases = [
        (90, [595.0 - 86.0, 36.0, 595.0 - 36.0, 236.0]),
        (
            180,
            [595.0 - 236.0, 842.0 - 86.0, 595.0 - 36.0, 842.0 - 36.0],
        ),
        (270, [36.0, 842.0 - 236.0, 86.0, 842.0 - 36.0]),
    ];
    for (angle, expected) in cases {
        let (_, rect) = default_signature_box(&rotated(angle)).unwrap();
        assert_eq!(rect, expected, "/Rotate {angle}");
    }
}

#[test]
fn small_page_clips_the_box() {
    let doc = open(1, |p| {
        p.set("MediaBox", vec![int(0), int(0), int(150), int(60)])
    });
    let (_, [llx, lly, urx, ury]) = default_signature_box(&doc).unwrap();
    assert!(llx >= 0.0 && lly >= 0.0 && urx <= 150.0 && ury <= 60.0);
    assert!(urx > llx && ury > lly);
}
