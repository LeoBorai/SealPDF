mod common;

use certsign_core::Error;
use certsign_pdf::{
    AppearanceSpec, FieldTarget, FontFamily, FontSpec, IncrementalWriter, PdfDocument,
    add_appearance, attach_signature, layout_text, set_widget_appearance, wrap,
};
use common::*;
use lopdf::{Object, dictionary};

fn helvetica(size: f32) -> FontSpec {
    FontSpec {
        family: FontFamily::Helvetica,
        size,
        ..Default::default()
    }
}

// ---- font options

#[test]
fn font_options_defaults_and_values() {
    let d = FontSpec::from_options(None, None, None, None).unwrap();
    assert_eq!(d, FontSpec::default());
    assert_eq!(
        (d.family, d.size, d.color),
        (FontFamily::Courier, 12.0, [0.0; 3])
    );

    let f =
        FontSpec::from_options(Some("Times"), Some(9.5), Some(1 | 2 | 4 | 8), Some("red")).unwrap();
    assert_eq!(f.family, FontFamily::Times);
    assert_eq!(f.size, 9.5);
    assert!(f.bold && f.italic && f.underline && f.strikethrough);
    assert_eq!(f.color, [1.0, 0.0, 0.0]);
    assert_eq!(f.base_font(), "Times-BoldItalic");
}

#[test]
fn font_colors() {
    let c = |n: &str| {
        FontSpec::from_options(None, None, None, Some(n))
            .unwrap()
            .color
    };
    assert_eq!(c("black"), [0.0; 3]);
    assert_eq!(c("WHITE"), [1.0; 3]);
    for name in ["lightGray", "gray", "darkGray", "pink"] {
        let v = c(name);
        assert!(v.iter().all(|x| (0.0..=1.0).contains(x)), "{name}");
    }
    assert_eq!(c("lightgray")[0], 192.0 / 255.0);
    assert_eq!(c("#00FF80"), [0.0, 1.0, 128.0 / 255.0]);
}

#[test]
fn font_option_errors() {
    for bad in [
        FontSpec::from_options(Some("comic"), None, None, None),
        FontSpec::from_options(None, Some(-1.0), None, None),
        FontSpec::from_options(None, None, Some(16), None),
        FontSpec::from_options(None, None, None, Some("purple")),
        FontSpec::from_options(None, None, None, Some("#12")),
    ] {
        assert!(matches!(bad, Err(Error::Options(_))), "{bad:?}");
    }
}

#[test]
fn base14_names() {
    let name = |fam: &str, style| {
        FontSpec::from_options(Some(fam), None, Some(style), None)
            .unwrap()
            .base_font()
    };
    assert_eq!(name("courier", 0), "Courier");
    assert_eq!(name("courier", 1), "Courier-Bold");
    assert_eq!(name("courier", 2), "Courier-Oblique");
    assert_eq!(name("helvetica", 3), "Helvetica-BoldOblique");
    assert_eq!(name("helvetica", 0), "Helvetica");
    assert_eq!(name("times", 0), "Times-Roman");
    assert_eq!(name("times", 1), "Times-Bold");
    assert_eq!(name("times", 2), "Times-Italic");
}

// ---- metrics and layout

#[test]
fn widths_use_afm_metrics() {
    // Helvetica: H 722, e 556, l 222, l 222, o 556.
    let w = helvetica(10.0).text_width("Hello", 10.0);
    assert!((w - 22.78).abs() < 1e-3, "{w}");
    // Courier is monospaced at 600.
    let c = FontSpec::default();
    assert!((c.text_width("abcd", 10.0) - 24.0).abs() < 1e-4);
    assert!((c.text_width("W", 10.0) - c.text_width("i", 10.0)).abs() < 1e-4);
    // Bold is wider than regular for Helvetica.
    let bold = FontSpec {
        bold: true,
        ..helvetica(10.0)
    };
    assert!(bold.text_width("Hello", 10.0) > w);
    // Accents map to Latin-1 widths; unmappable characters count as '?'.
    let h = helvetica(10.0);
    assert_eq!(h.text_width("é", 10.0), h.text_width("e", 10.0));
    assert_eq!(h.text_width("漢", 10.0), h.text_width("?", 10.0));
}

#[test]
fn wraps_at_spaces() {
    let f = FontSpec::default(); // 7.2 pt per char at size 12
    let lines = wrap(&f, "uno dos tres cuatro", 12.0, 72.0); // 10 chars per line
    assert_eq!(lines, ["uno dos", "tres", "cuatro"]);
    assert_eq!(wrap(&f, "", 12.0, 72.0), [""]);
}

#[test]
fn wraps_newlines_and_long_words() {
    let f = FontSpec::default();
    assert_eq!(wrap(&f, "a\nb\r\nc\rd", 12.0, 72.0), ["a", "b", "c", "d"]);
    assert_eq!(wrap(&f, "a\n\nb", 12.0, 72.0), ["a", "", "b"]);
    // A 25-character word is cut every 10 characters.
    assert_eq!(
        wrap(&f, &"x".repeat(25), 12.0, 72.0),
        ["x".repeat(10), "x".repeat(10), "x".repeat(5)]
    );
}

#[test]
fn layout_keeps_size_when_text_fits() {
    let l = layout_text(&helvetica(12.0), "Firmado", 196.0, 46.0);
    assert_eq!(l.size, 12.0);
    assert_eq!(l.lines, ["Firmado"]);
}

#[test]
fn layout_shrinks_to_fit() {
    let text = "Firmado digitalmente por PEREZ GARCIA JUAN - 12345678Z\nFecha: 05/03/24 15:07\nMotivo: Aprobado";
    let f = helvetica(12.0);
    let l = layout_text(&f, text, 196.0, 46.0);
    assert!(l.size < 12.0, "{}", l.size);
    assert!(
        l.lines.len() as f32 * l.size <= 46.0 + 1e-3,
        "lines fit the height"
    );
    for line in &l.lines {
        assert!(
            f.text_width(line, l.size) <= 196.0 + 1e-3,
            "{line:?} fits the width"
        );
    }
    // Within the 10 % search precision of the largest size that fits.
    let bigger = l.size * 1.12;
    assert!(wrap(&f, text, bigger, 196.0).len() as f32 * bigger > 46.0 + 1e-3 || bigger > 12.0);
}

#[test]
fn layout_with_size_zero_fills_the_box() {
    let f = FontSpec {
        size: 0.0,
        ..helvetica(0.0)
    };
    let l = layout_text(&f, "Hi", 196.0, 46.0);
    assert!((l.size - 45.999).abs() < 0.01, "{}", l.size);
    let two = layout_text(&f, "Hi\nthere", 196.0, 46.0);
    assert!(two.size <= 23.0 + 1e-3, "{}", two.size);
}

// ---- appearance streams

fn plain_doc() -> Vec<u8> {
    let (mut doc, _) = base(1);
    save(&mut doc)
}

/// Signs into a new field with the given appearance; returns the output file and the AP stream.
fn sign_with(
    spec: AppearanceSpec<'_>,
) -> certsign_core::Result<(Vec<u8>, lopdf::Stream, lopdf::Dictionary)> {
    let bytes = plain_doc();
    let pdf = PdfDocument::open(bytes, None)?;
    let mut w = IncrementalWriter::new(&pdf)?;
    let sig = w.add_signature(
        dictionary! { "Type" => "Sig", "Filter" => "Adobe.PPKLite", "SubFilter" => "adbe.pkcs7.detached" },
        256,
    )?;
    let field = attach_signature(
        &mut w,
        &FieldTarget::New {
            page: 1,
            rect: Some([50.0, 50.0, 50.0 + spec.width, 50.0 + spec.height]),
        },
        sig,
    )?;
    let form = add_appearance(&mut w, &spec)?;
    set_widget_appearance(&mut w, field.widget_id, form)?;
    let out = w.finish_signature()?.embed(&[0x30, 0])?;

    let reopened = PdfDocument::open(out.clone(), None)?;
    let doc = reopened.document();
    let widget = doc.get_dictionary(field.widget_id).unwrap();
    let ap = widget.get(b"AP").unwrap().as_dict().unwrap();
    let n = ap.get(b"N").unwrap().as_reference().unwrap();
    assert_eq!(n, form);
    let stream = doc.get_object(n).unwrap().as_stream().unwrap().clone();
    let resources = stream
        .dict
        .get(b"Resources")
        .unwrap()
        .as_dict()
        .unwrap()
        .clone();
    Ok((out, stream, resources))
}

fn spec<'a>(text: Option<&'a str>, font: FontSpec) -> AppearanceSpec<'a> {
    AppearanceSpec {
        width: 200.0,
        height: 50.0,
        text,
        font,
        image: None,
        rotation: 0,
    }
}

fn content(s: &lopdf::Stream) -> String {
    String::from_utf8(s.content.clone()).unwrap()
}

#[test]
fn text_only_content_stream_snapshot() {
    let (_, stream, resources) = sign_with(spec(Some("Hola"), helvetica(10.0))).unwrap();
    assert_eq!(
        content(&stream),
        "0.000 0.000 0.000 rg 0.000 0.000 0.000 RG\n\
         BT /F1 10 Tf\n\
         1 0 0 1 2 38 Tm (Hola) Tj\n\
         ET\n"
    );
    assert_eq!(
        stream.dict.get(b"Subtype").unwrap().as_name().unwrap(),
        b"Form"
    );
    let bbox: Vec<f32> = stream
        .dict
        .get(b"BBox")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o.as_float().unwrap())
        .collect();
    assert_eq!(bbox, [0.0, 0.0, 200.0, 50.0]);
    let font = resources
        .get(b"Font")
        .unwrap()
        .as_dict()
        .unwrap()
        .get(b"F1")
        .unwrap()
        .as_dict()
        .unwrap();
    assert_eq!(
        font.get(b"BaseFont").unwrap().as_name().unwrap(),
        b"Helvetica"
    );
    assert_eq!(
        font.get(b"Encoding").unwrap().as_name().unwrap(),
        b"WinAnsiEncoding"
    );
}

#[test]
fn multiline_color_and_escaping() {
    let font = FontSpec::from_options(Some("times"), Some(8.0), Some(1), Some("red")).unwrap();
    let (_, stream, resources) = sign_with(spec(Some("a (b) \\ c\nÑandú €"), font)).unwrap();
    let c = content(&stream);
    assert!(
        c.starts_with("1.000 0.000 0.000 rg 1.000 0.000 0.000 RG\nBT /F1 8 Tf\n"),
        "{c}"
    );
    assert!(c.contains("1 0 0 1 2 40 Tm (a \\(b\\) \\\\ c) Tj\n"), "{c}");
    // Second baseline one font size lower; Ñ is 0xD1 (octal 321) and € is 0x80 (octal 200).
    assert!(
        c.contains("1 0 0 1 2 32 Tm (\\321and\\372 \\200) Tj\n"),
        "{c}"
    );
    let font = resources
        .get(b"Font")
        .unwrap()
        .as_dict()
        .unwrap()
        .get(b"F1")
        .unwrap()
        .as_dict()
        .unwrap();
    assert_eq!(
        font.get(b"BaseFont").unwrap().as_name().unwrap(),
        b"Times-Bold"
    );
}

#[test]
fn underline_and_strikethrough() {
    let font = FontSpec::from_options(Some("helvetica"), Some(10.0), Some(4 | 8), None).unwrap();
    let (_, stream, _) = sign_with(spec(Some("Hola"), font)).unwrap();
    let c = content(&stream);
    let width = helvetica(10.0).text_width("Hola", 10.0); // H 722 + o 556 + l 222 + a 556
    assert!((width - 20.56).abs() < 1e-3);
    assert!(c.contains("ET\n0.5 w\n"), "{c}");
    assert_eq!(c.matches(" l S\n").count(), 2, "{c}");
    assert!(c.contains("2 36.8 m 22.56 36.8 l S"), "underline: {c}");
    assert!(c.contains("2 41 m 22.56 41 l S"), "strikethrough: {c}");
}

#[test]
fn long_text_shrinks_inside_the_box() {
    let text = "Firmado digitalmente por PEREZ GARCIA JUAN - 12345678Z\nFecha: 05/03/24 15:07\nMotivo: Aprobado";
    let (_, stream, _) = sign_with(spec(Some(text), helvetica(12.0))).unwrap();
    let c = content(&stream);
    let size: f32 = c
        .split("BT /F1 ")
        .nth(1)
        .unwrap()
        .split(" Tf")
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(size < 12.0 && size > 3.0, "{size}");
    // Every baseline stays inside the 2 pt margin.
    for tm in c.lines().filter(|l| l.contains(" Tm ")) {
        let y: f32 = tm.split_whitespace().nth(5).unwrap().parse().unwrap();
        assert!((2.0 - 1e-3..=48.0).contains(&y), "{tm}");
    }
}

#[test]
fn rotation_matrices() {
    // 90/270 swap the canvas: text is laid out in 50 x 200 and then rotated into 200 x 50.
    let expected = [
        (0, None),
        (90, Some("q 0 1 -1 0 200 0 cm\n")),
        (180, Some("q -1 0 0 -1 200 50 cm\n")),
        (270, Some("q 0 -1 1 0 0 50 cm\n")),
    ];
    for (rotation, head) in expected {
        let s = AppearanceSpec {
            rotation,
            ..spec(Some("Hi"), helvetica(10.0))
        };
        let (_, stream, _) = sign_with(s).unwrap();
        let c = content(&stream);
        match head {
            None => assert!(!c.contains(" cm\n"), "{c}"),
            Some(h) => {
                assert!(c.starts_with(h), "{rotation}: {c}");
                assert!(c.ends_with("Q\n"), "{rotation}: {c}");
            }
        }
    }
    // The 90 degree canvas is 50 high x 200 wide when rotated: text sits 10 pt below its top.
    let s = AppearanceSpec {
        rotation: 90,
        ..spec(Some("Hi"), helvetica(10.0))
    };
    let c = content(&sign_with(s).unwrap().1);
    assert!(c.contains("1 0 0 1 2 188 Tm (Hi) Tj"), "{c}");
}

#[test]
fn rejects_bad_rotation_and_empty_rectangle() {
    let err = sign_with(AppearanceSpec {
        rotation: 45,
        ..spec(Some("x"), FontSpec::default())
    })
    .unwrap_err();
    assert!(matches!(err, Error::Options(_)), "{err}");
    let err = sign_with(AppearanceSpec {
        width: 0.0,
        ..spec(Some("x"), FontSpec::default())
    });
    assert!(err.is_err());
}

#[test]
fn no_text_and_no_image_is_an_empty_appearance() {
    let (_, stream, _) = sign_with(spec(None, FontSpec::default())).unwrap();
    assert_eq!(content(&stream), "");
    let (_, stream, _) = sign_with(spec(Some(""), FontSpec::default())).unwrap();
    assert_eq!(content(&stream), "");
}

fn png(color: png::ColorType, data: &[u8], w: u32, h: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = png::Encoder::new(&mut out, w, h);
    enc.set_color(color);
    enc.set_depth(png::BitDepth::Eight);
    let mut writer = enc.write_header().unwrap();
    writer.write_image_data(data).unwrap();
    writer.finish().unwrap();
    out
}

#[test]
fn rubric_image_is_centered_and_scaled() {
    // A 4 x 2 RGBA image in a 200 x 50 box: scale min(50, 25) = 25 -> 100 x 50, x offset 50.
    let img = png(png::ColorType::Rgba, &[255; 4 * 2 * 4], 4, 2);
    let s = AppearanceSpec {
        image: Some(&img),
        ..spec(None, FontSpec::default())
    };
    let (out, stream, resources) = sign_with(s).unwrap();
    assert_eq!(content(&stream), "q 100 0 0 50 50 0 cm /Im1 Do Q\n");

    let pdf = PdfDocument::open(out, None).unwrap();
    let im = resources
        .get(b"XObject")
        .unwrap()
        .as_dict()
        .unwrap()
        .get(b"Im1")
        .unwrap()
        .as_reference()
        .unwrap();
    let image = pdf.document().get_object(im).unwrap().as_stream().unwrap();
    assert_eq!(image.dict.get(b"Width").unwrap().as_i64().unwrap(), 4);
    assert_eq!(image.dict.get(b"Height").unwrap().as_i64().unwrap(), 2);
    let mask = image.dict.get(b"SMask").unwrap().as_reference().unwrap();
    let mask = pdf
        .document()
        .get_object(mask)
        .unwrap()
        .as_stream()
        .unwrap();
    assert_eq!(
        mask.dict.get(b"ColorSpace").unwrap().as_name().unwrap(),
        b"DeviceGray"
    );
    // Decoded pixel data round-trips.
    assert_eq!(image.get_plain_content().unwrap(), vec![255; 4 * 2 * 3]);
    assert_eq!(mask.get_plain_content().unwrap(), vec![255; 4 * 2]);
}

#[test]
fn image_under_text_and_rotated_canvas() {
    let img = png(png::ColorType::Rgb, &[10; 2 * 2 * 3], 2, 2);
    let s = AppearanceSpec {
        image: Some(&img),
        rotation: 90,
        ..spec(Some("Hi"), helvetica(10.0))
    };
    let (_, stream, _) = sign_with(s).unwrap();
    let c = content(&stream);
    // Canvas is 50 x 200: a square image scales to 50 and is centered vertically at y = 75.
    assert!(c.contains("q 50 0 0 50 0 75 cm /Im1 Do Q\n"), "{c}");
    assert!(
        c.find("Do").unwrap() < c.find("BT").unwrap(),
        "image is drawn first"
    );
}

#[test]
fn bad_image_is_an_error() {
    let s = AppearanceSpec {
        image: Some(b"not an image"),
        ..spec(None, FontSpec::default())
    };
    assert!(sign_with(s).is_err());
}

#[test]
fn result_is_a_well_formed_pdf_and_signature_still_covers_the_file() {
    let (out, _, _) = sign_with(spec(Some("Hola"), helvetica(10.0))).unwrap();
    let pdf = PdfDocument::open(out.clone(), None).unwrap();
    assert_eq!(pdf.signatures().len(), 1);
    let range = pdf.signatures()[0]
        .value
        .as_ref()
        .unwrap()
        .byte_range
        .clone()
        .unwrap();
    assert_eq!((range[2] + range[3]) as usize, out.len());
    assert!(matches!(
        pdf.document().get_object((1, 0)),
        Ok(Object::Dictionary(_)) | Ok(Object::Stream(_)) | Err(_)
    ));
}

/// Writes sample PDFs for visual inspection when `CERTSIGN_KEEP_DIR` is set.
#[test]
fn keep_samples_for_inspection() {
    let Ok(dir) = std::env::var("CERTSIGN_KEEP_DIR") else {
        return;
    };
    let img = png(
        png::ColorType::Rgba,
        &[200, 30, 30, 90].repeat(16 * 8),
        16,
        8,
    );
    let text = "Firmado digitalmente por\nPEREZ GARCIA JUAN - 12345678Z\nFecha: 05/03/24 15:07\nMotivo: Aprobado";
    let cases: Vec<(&str, AppearanceSpec<'_>)> = vec![
        ("ap-text.pdf", spec(Some(text), helvetica(10.0))),
        ("ap-fit.pdf", spec(Some(text), helvetica(18.0))),
        (
            "ap-style.pdf",
            spec(
                Some(text),
                FontSpec::from_options(Some("times"), Some(9.0), Some(1 | 4), Some("red")).unwrap(),
            ),
        ),
        (
            "ap-image.pdf",
            AppearanceSpec {
                image: Some(&img),
                ..spec(Some(text), helvetica(9.0))
            },
        ),
        (
            "ap-rot90.pdf",
            AppearanceSpec {
                rotation: 90,
                ..spec(Some(text), helvetica(9.0))
            },
        ),
        (
            "ap-rot180.pdf",
            AppearanceSpec {
                rotation: 180,
                ..spec(Some(text), helvetica(9.0))
            },
        ),
        (
            "ap-rot270.pdf",
            AppearanceSpec {
                rotation: 270,
                image: Some(&img),
                ..spec(Some(text), helvetica(9.0))
            },
        ),
    ];
    for (name, s) in cases {
        let (out, _, _) = sign_with(s).unwrap();
        std::fs::write(std::path::Path::new(&dir).join(name), out).unwrap();
    }
}
