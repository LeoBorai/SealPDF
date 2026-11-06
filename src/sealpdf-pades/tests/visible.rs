mod common;

use chrono::{FixedOffset, TimeZone, Utc};
use common::{Leaf, Pki, blank_pdf};
use lopdf::{Document, Object, content::Content};
use sealpdf_cms::verify_detached;
use sealpdf_core::{ErrorCode, FixedClock};
use sealpdf_keystore::{NoPrompt, Pkcs12KeyStore, StaticPrompt};
use sealpdf_pades::{Placement, SigningParams, VisibleSignature, sign_pdf};
use sealpdf_pdf::PdfDocument;

const AT: (i32, u32, u32, u32, u32) = (2026, 3, 4, 23, 30);

fn store(pki: &Pki, leaf: &Leaf) -> Pkcs12KeyStore {
    let path = pki.p12(leaf, "pw", &[]);
    Pkcs12KeyStore::open(path, &StaticPrompt::new("pw")).unwrap()
}

fn params(placement: Option<Placement>, offset_hours: i32) -> SigningParams {
    SigningParams {
        visible: Some(VisibleSignature {
            placement,
            utc_offset: FixedOffset::east_opt(offset_hours * 3600).unwrap(),
        }),
        ..SigningParams::default()
    }
}

fn sign(
    pdf: &[u8],
    pki: &Pki,
    leaf: &Leaf,
    params: &SigningParams,
) -> sealpdf_core::Result<Vec<u8>> {
    let (y, mo, d, h, mi) = AT;
    let clock = FixedClock(Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap());
    sign_pdf(
        pdf.to_vec(),
        &store(pki, leaf),
        &leaf.name,
        &clock,
        &NoPrompt,
        params,
    )
}

/// `blank_pdf` with `/Rotate` on every page.
fn rotated_pdf(pages: usize, angle: i64) -> Vec<u8> {
    let mut doc = Document::load_mem(&blank_pdf(pages, false)).unwrap();
    let ids: Vec<_> = doc.get_pages().into_values().collect();
    for id in ids {
        doc.get_object_mut(id)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("Rotate", angle);
    }
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}

/// What the last signature's widget looks like in `file`.
struct Widget {
    page: Option<u32>,
    rect: [f32; 4],
    bbox: Vec<f32>,
    content: Vec<u8>,
}

fn widget(file: &[u8]) -> Widget {
    let pdf = PdfDocument::open(file.to_vec(), None).unwrap();
    let sig = pdf.signatures().pop().unwrap();
    let doc = pdf.document();
    let dict = doc.get_dictionary(sig.id).unwrap();
    let n = dict
        .get(b"AP")
        .and_then(Object::as_dict)
        .and_then(|ap| ap.get(b"N"))
        .and_then(Object::as_reference)
        .expect("a normal appearance");
    let stream = doc.get_object(n).unwrap().as_stream().unwrap();
    let bbox = stream
        .dict
        .get(b"BBox")
        .and_then(Object::as_array)
        .unwrap()
        .iter()
        .map(|o| o.as_float().unwrap())
        .collect();
    Widget {
        page: sig.page,
        rect: sig.rect.unwrap(),
        bbox,
        content: stream
            .decompressed_content()
            .unwrap_or_else(|_| stream.content.clone()),
    }
}

/// The text the appearance draws, its lines joined by a space. The font is WinAnsi, which for
/// these letters is Latin-1.
fn drawn_text(content: &[u8]) -> String {
    let lines: Vec<String> = Content::decode(content)
        .unwrap()
        .operations
        .iter()
        .filter(|op| op.operator == "Tj")
        .filter_map(|op| match op.operands.first() {
            Some(Object::String(bytes, _)) => Some(bytes.iter().map(|b| char::from(*b)).collect()),
            _ => None,
        })
        .collect();
    lines.join(" ")
}

fn code(e: sealpdf_core::Error) -> Option<ErrorCode> {
    e.code()
}

#[test]
fn default_box_on_the_last_page_with_the_autofirma_text() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("Ada Lovelace", None);
    let input = blank_pdf(2, false);
    // 23:30 UTC is already the next day at +01:00.
    let out = sign(&input, &pki, &leaf, &params(None, 1)).unwrap();

    assert_eq!(out[..input.len()], input[..], "the input is kept as is");
    let w = widget(&out);
    assert_eq!(w.page, Some(2));
    assert_eq!(w.rect, [36.0, 36.0, 236.0, 86.0]);
    assert_eq!(w.bbox, [0.0, 0.0, 200.0, 50.0]);
    assert_eq!(
        drawn_text(&w.content),
        "Firmado por Ada Lovelace el d\u{ed}a 05/03/2026 con un certificado emitido por Intermediate CA"
    );
    assert!(
        !String::from_utf8_lossy(&w.content).contains(" cm"),
        "unrotated page"
    );

    // Only the stamp is new: neither page gets a content stream.
    let doc = PdfDocument::open(out, None).unwrap();
    for page in doc.pages() {
        let dict = doc.document().get_dictionary(page.id).unwrap();
        assert!(!dict.has(b"Contents"), "page {} content", page.number);
    }
}

#[test]
fn the_date_uses_the_given_offset() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("Ada Lovelace", None);
    let input = blank_pdf(1, false);
    for (hours, day) in [(0, "04/03/2026"), (1, "05/03/2026"), (-5, "04/03/2026")] {
        let out = sign(&input, &pki, &leaf, &params(None, hours)).unwrap();
        let text = drawn_text(&widget(&out).content);
        assert!(
            text.contains(&format!("el d\u{ed}a {day} con")),
            "{hours}: {text}"
        );
    }
}

#[test]
fn a_caller_rectangle_is_used_as_given() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("Ada Lovelace", None);
    let place = Placement {
        page: 1,
        rect: [300.0, 400.0, 500.0, 460.0],
    };
    let out = sign(&blank_pdf(3, false), &pki, &leaf, &params(Some(place), 0)).unwrap();
    let w = widget(&out);
    assert_eq!(w.page, Some(1));
    assert_eq!(w.rect, place.rect);
    assert_eq!(w.bbox, [0.0, 0.0, 200.0, 60.0]);
}

#[test]
fn a_rectangle_on_a_rotated_page_is_in_user_space() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("Ada Lovelace", None);
    let place = Placement {
        page: 1,
        rect: [400.0, 700.0, 550.0, 800.0],
    };
    let out = sign(&rotated_pdf(1, 90), &pki, &leaf, &params(Some(place), 0)).unwrap();
    assert_eq!(widget(&out).rect, place.rect);
}

#[test]
fn bad_places_are_refused_and_write_nothing() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("Ada Lovelace", None);
    let input = blank_pdf(3, false);
    let cases = [
        (
            Placement {
                page: 1,
                rect: [700.0, 900.0, 800.0, 950.0],
            },
            ErrorCode::INVALID_SIGNATURE_POSITION,
        ),
        (
            Placement {
                page: 1,
                rect: [50.0, 50.0, 50.0, 90.0],
            },
            ErrorCode::INVALID_SIGNATURE_POSITION,
        ),
        (
            Placement {
                page: 5,
                rect: [50.0, 50.0, 250.0, 100.0],
            },
            ErrorCode::INVALID_SIGNATURE_PAGE,
        ),
        (
            Placement {
                page: 0,
                rect: [50.0, 50.0, 250.0, 100.0],
            },
            ErrorCode::INVALID_SIGNATURE_PAGE,
        ),
    ];
    for (place, expected) in cases {
        let err = sign(&input, &pki, &leaf, &params(Some(place), 0)).unwrap_err();
        assert_eq!(code(err), Some(expected), "{place:?}");
    }
}

#[test]
fn the_text_is_turned_with_a_rotated_page() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("Ada Lovelace", None);
    let out = sign(&rotated_pdf(1, 90), &pki, &leaf, &params(None, 0)).unwrap();
    let w = widget(&out);
    // The displayed lower-left corner of a page turned by 90 is its top-left in user space.
    assert_eq!(w.rect, [509.0, 36.0, 559.0, 236.0]);
    assert_eq!(w.bbox, [0.0, 0.0, 50.0, 200.0]);
    let content = String::from_utf8_lossy(&w.content);
    assert!(content.starts_with("q 0 1 -1 0 50 0 cm"), "{content}");
    assert!(drawn_text(&w.content).starts_with("Firmado por Ada Lovelace"));

    for angle in [180, 270] {
        let out = sign(&rotated_pdf(1, angle), &pki, &leaf, &params(None, 0)).unwrap();
        let content = String::from_utf8_lossy(&widget(&out).content).into_owned();
        assert!(content.starts_with("q "), "{angle}: {content}");
        assert!(content.contains(" cm"), "{angle}: {content}");
    }
}

#[test]
fn the_text_shrinks_to_fit_a_small_box() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("Ada Lovelace", None);
    let place = Placement {
        page: 1,
        rect: [50.0, 50.0, 130.0, 90.0],
    };
    let out = sign(&blank_pdf(1, false), &pki, &leaf, &params(Some(place), 0)).unwrap();
    let w = widget(&out);
    let text = drawn_text(&w.content);
    assert!(text.starts_with("Firmado por Ada Lovelace"), "{text}");
    assert!(text.ends_with("Intermediate CA"), "{text}");
}

#[test]
fn a_visible_signature_keeps_the_earlier_one_valid() {
    let Some(pki) = Pki::new() else { return };
    let a = pki.leaf("alice", None);
    let b = pki.leaf("bob", Some("P-256"));
    let first = sign(&blank_pdf(1, false), &pki, &a, &SigningParams::default()).unwrap();
    let both = sign(&first, &pki, &b, &params(None, 0)).unwrap();
    assert_eq!(both[..first.len()], first[..]);

    let pdf = PdfDocument::open(both.clone(), None).unwrap();
    let sigs = pdf.signatures();
    assert_eq!(sigs.len(), 2);
    for sig in &sigs {
        let value = sig.value.as_ref().unwrap();
        let r = value.byte_range.clone().unwrap();
        let (r0, r1, r2, r3) = (r[0] as usize, r[1] as usize, r[2] as usize, r[3] as usize);
        let hex = std::str::from_utf8(&both[r1 + 1..r2 - 1]).unwrap();
        let cms: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let covered = [&both[r0..r1], &both[r2..r2 + r3]].concat();
        assert!(verify_detached(&cms, &covered).is_ok(), "{}", sig.name);
    }
}

#[test]
fn a_visible_signature_is_valid_for_other_tools() {
    let Some(pki) = Pki::new() else { return };
    if !common::pyhanko_available() {
        return;
    }
    let fixture = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/input.pdf"),
    )
    .unwrap();
    let on_first_page = Placement {
        page: 1,
        rect: [50.0, 50.0, 250.0, 100.0],
    };
    let leaf = pki.leaf("visible", None);
    for (label, input) in [("blank", blank_pdf(3, false)), ("fixture", fixture)] {
        // Page 1 with a given rectangle, and the last page with the default box.
        for place in [Some(on_first_page), None] {
            let out = sign(&input, &pki, &leaf, &params(place, 0)).unwrap();
            let w = widget(&out);
            assert_ne!(w.rect, [0.0; 4], "{label}");
            let sigs = common::pyhanko_validate(pki.path(), &out);
            assert_eq!(sigs.len(), 1, "{label} {place:?}");
            assert!(
                sigs[0].intact && sigs[0].valid && sigs[0].entire_file,
                "{label} {place:?}: {:?}",
                sigs[0]
            );
        }
    }
}
