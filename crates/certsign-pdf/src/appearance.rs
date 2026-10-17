//! Appearance stream of a visible signature: rubric image under wrapped, fitted text.

use crate::{IncrementalWriter, font_metrics as fm, image};
use certsign_core::{Error, Result};
use lopdf::{Dictionary, Object, ObjectId, Stream};
use std::fmt::Write as _;

/// Gap kept between the text and the signature box.
const MARGIN: f32 = 2.0;
const DEFAULT_SIZE: f32 = 12.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FontFamily {
    Courier,
    Helvetica,
    Times,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FontSpec {
    pub family: FontFamily,
    /// Maximum size in points. `0` fits the text to the box with no upper bound.
    pub size: f32,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strikethrough: bool,
    pub color: [f32; 3],
}

impl Default for FontSpec {
    fn default() -> Self {
        Self {
            family: FontFamily::Courier,
            size: DEFAULT_SIZE,
            bold: false,
            italic: false,
            underline: false,
            strikethrough: false,
            color: [0.0; 3],
        }
    }
}

fn options_err(msg: String) -> Error {
    Error::Options(msg)
}

impl FontSpec {
    /// Builds a font from the `visible.font_*` options. Absent values take the defaults:
    /// Courier, 12 pt, normal, black.
    ///
    /// `style` is a bit set: 1 bold, 2 italic, 4 underline, 8 strikethrough.
    /// `color` is one of `black`, `white`, `lightGray`, `gray`, `darkGray`, `red`, `pink`
    /// (any case), or `#RRGGBB`.
    pub fn from_options(
        family: Option<&str>,
        size: Option<f32>,
        style: Option<u32>,
        color: Option<&str>,
    ) -> Result<Self> {
        let mut font = Self::default();
        if let Some(f) = family {
            font.family = match f.to_ascii_lowercase().as_str() {
                "courier" => FontFamily::Courier,
                "helvetica" => FontFamily::Helvetica,
                "times" => FontFamily::Times,
                other => {
                    return Err(options_err(format!(
                        "visible.font_family {other:?}: expected courier, helvetica or times"
                    )));
                }
            };
        }
        if let Some(s) = size {
            if !s.is_finite() || s < 0.0 {
                return Err(options_err(format!(
                    "visible.font_size {s}: must be 0 or more"
                )));
            }
            font.size = s;
        }
        if let Some(bits) = style {
            if bits & !0b1111 != 0 {
                return Err(options_err(format!(
                    "visible.font_style {bits}: only bits 1, 2, 4 and 8 exist"
                )));
            }
            font.bold = bits & 1 != 0;
            font.italic = bits & 2 != 0;
            font.underline = bits & 4 != 0;
            font.strikethrough = bits & 8 != 0;
        }
        if let Some(c) = color {
            font.color = parse_color(c)?;
        }
        Ok(font)
    }

    fn widths(&self) -> &'static [u16; 256] {
        match (self.family, self.bold, self.italic) {
            (FontFamily::Courier, false, false) => &fm::COURIER,
            (FontFamily::Courier, true, false) => &fm::COURIER_BOLD,
            (FontFamily::Courier, false, true) => &fm::COURIER_OBLIQUE,
            (FontFamily::Courier, true, true) => &fm::COURIER_BOLD_OBLIQUE,
            (FontFamily::Helvetica, false, false) => &fm::HELVETICA,
            (FontFamily::Helvetica, true, false) => &fm::HELVETICA_BOLD,
            (FontFamily::Helvetica, false, true) => &fm::HELVETICA_OBLIQUE,
            (FontFamily::Helvetica, true, true) => &fm::HELVETICA_BOLD_OBLIQUE,
            (FontFamily::Times, false, false) => &fm::TIMES_ROMAN,
            (FontFamily::Times, true, false) => &fm::TIMES_BOLD,
            (FontFamily::Times, false, true) => &fm::TIMES_ITALIC,
            (FontFamily::Times, true, true) => &fm::TIMES_BOLD_ITALIC,
        }
    }

    /// PostScript name of the base-14 face.
    pub fn base_font(&self) -> &'static str {
        match (self.family, self.bold, self.italic) {
            (FontFamily::Courier, false, false) => "Courier",
            (FontFamily::Courier, true, false) => "Courier-Bold",
            (FontFamily::Courier, false, true) => "Courier-Oblique",
            (FontFamily::Courier, true, true) => "Courier-BoldOblique",
            (FontFamily::Helvetica, false, false) => "Helvetica",
            (FontFamily::Helvetica, true, false) => "Helvetica-Bold",
            (FontFamily::Helvetica, false, true) => "Helvetica-Oblique",
            (FontFamily::Helvetica, true, true) => "Helvetica-BoldOblique",
            (FontFamily::Times, false, false) => "Times-Roman",
            (FontFamily::Times, true, false) => "Times-Bold",
            (FontFamily::Times, false, true) => "Times-Italic",
            (FontFamily::Times, true, true) => "Times-BoldItalic",
        }
    }

    fn code_width(&self, code: u8) -> f32 {
        let w = self.widths()[usize::from(code)];
        let w = if w == 0 && (0x80..=0x9F).contains(&code) {
            // Windows-1252 extras are missing from the Latin-1 tables.
            if self.family == FontFamily::Courier {
                600
            } else {
                556
            }
        } else {
            w
        };
        f32::from(w) / 1000.0
    }

    /// Width in points of `text` at `size`.
    pub fn text_width(&self, text: &str, size: f32) -> f32 {
        text.chars()
            .map(|c| self.code_width(winansi(c)))
            .sum::<f32>()
            * size
    }
}

fn parse_color(name: &str) -> Result<[f32; 3]> {
    let rgb = |r: u8, g: u8, b: u8| {
        [
            f32::from(r) / 255.0,
            f32::from(g) / 255.0,
            f32::from(b) / 255.0,
        ]
    };
    if let Some(hex) = name.strip_prefix('#') {
        if hex.len() == 6
            && let Ok(v) = u32::from_str_radix(hex, 16)
        {
            return Ok(rgb((v >> 16) as u8, (v >> 8) as u8, v as u8));
        }
        return Err(options_err(format!(
            "visible.font_color {name:?}: expected #RRGGBB"
        )));
    }
    Ok(match name.to_ascii_lowercase().as_str() {
        "black" => rgb(0, 0, 0),
        "white" => rgb(255, 255, 255),
        "lightgray" => rgb(192, 192, 192),
        "gray" => rgb(128, 128, 128),
        "darkgray" => rgb(64, 64, 64),
        "red" => rgb(255, 0, 0),
        "pink" => rgb(255, 175, 175),
        _ => {
            return Err(options_err(format!(
                "visible.font_color {name:?}: expected black, white, lightGray, gray, darkGray, red, pink or #RRGGBB"
            )));
        }
    })
}

/// Maps a character to its Windows-1252 code; unmappable characters become `?`.
pub(crate) fn winansi(c: char) -> u8 {
    match c {
        '\t' => b' ',
        ' '..='~' | '\u{A0}'..='\u{FF}' => c as u32 as u8,
        '€' => 0x80,
        '‚' => 0x82,
        'ƒ' => 0x83,
        '„' => 0x84,
        '…' => 0x85,
        '†' => 0x86,
        '‡' => 0x87,
        'ˆ' => 0x88,
        '‰' => 0x89,
        'Š' => 0x8A,
        '‹' => 0x8B,
        'Œ' => 0x8C,
        'Ž' => 0x8E,
        '‘' => 0x91,
        '’' => 0x92,
        '“' => 0x93,
        '”' => 0x94,
        '•' => 0x95,
        '–' => 0x96,
        '—' => 0x97,
        '˜' => 0x98,
        '™' => 0x99,
        'š' => 0x9A,
        '›' => 0x9B,
        'œ' => 0x9C,
        'ž' => 0x9E,
        'Ÿ' => 0x9F,
        _ => b'?',
    }
}

/// Splits `text` into lines no wider than `width`, breaking at spaces (and inside words that
/// are wider than a line). Newlines (`\n`, `\r\n`, `\r`) start a new line.
pub fn wrap(font: &FontSpec, text: &str, size: f32, width: f32) -> Vec<String> {
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines = Vec::new();
    for paragraph in normalized.split('\n') {
        let mut line = String::new();
        let mut line_w = 0.0;
        for word in paragraph.split(' ') {
            let word_w = font.text_width(word, size);
            let space_w = font.text_width(" ", size);
            let needed = if line.is_empty() {
                word_w
            } else {
                line_w + space_w + word_w
            };
            if needed <= width + 1e-3 {
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(word);
                line_w = needed;
                continue;
            }
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            // Break a word that does not fit on a line of its own.
            let mut chunk = String::new();
            let mut chunk_w = 0.0;
            for ch in word.chars() {
                let cw = font.text_width(ch.encode_utf8(&mut [0; 4]), size);
                if chunk_w + cw > width + 1e-3 && !chunk.is_empty() {
                    lines.push(std::mem::take(&mut chunk));
                    chunk_w = 0.0;
                }
                chunk.push(ch);
                chunk_w += cw;
            }
            line = chunk;
            line_w = chunk_w;
        }
        lines.push(line);
    }
    lines
}

/// Text laid out inside a box.
#[derive(Debug, Clone, PartialEq)]
pub struct TextLayout {
    pub size: f32,
    pub lines: Vec<String>,
}

fn fits(font: &FontSpec, text: &str, size: f32, width: f32, height: f32) -> Option<Vec<String>> {
    let lines = wrap(font, text, size, width);
    (lines.len() as f32 * size <= height + 1e-3).then_some(lines)
}

/// Fits `text` into `width` x `height` by shrinking the font from `font.size` until it fits,
/// searching to 10 % precision, like the AutoFirma implementation.
pub fn layout_text(font: &FontSpec, text: &str, width: f32, height: f32) -> TextLayout {
    let mut max = font.size;
    if max <= 0.0 {
        let newlines = text.matches('\n').count().max(text.matches('\r').count());
        max = height.abs() / (newlines + 1) as f32 - 0.001;
    }
    if let Some(lines) = fits(font, text, max, width, height) {
        return TextLayout { size: max, lines };
    }
    let (mut lo, mut hi) = (0.0f32, max);
    let mut size = max;
    for _ in 0..50 {
        size = (lo + hi) / 2.0;
        if fits(font, text, size, width, height).is_some() {
            if hi - lo < size * 0.1 {
                break;
            }
            lo = size;
        } else {
            hi = size;
        }
    }
    let lines = wrap(font, text, size, width);
    TextLayout { size, lines }
}

#[derive(Debug, Clone)]
pub struct AppearanceSpec<'a> {
    /// Width and height of the signature rectangle.
    pub width: f32,
    pub height: f32,
    /// Text after placeholder expansion.
    pub text: Option<&'a str>,
    pub font: FontSpec,
    /// JPEG or PNG bytes of the rubric.
    pub image: Option<&'a [u8]>,
    /// Counter-clockwise rotation of the content: 0, 90, 180 or 270.
    pub rotation: u32,
}

fn num(out: &mut String, n: f32) {
    let s = format!("{n:.3}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    out.push_str(if s.is_empty() || s == "-" { "0" } else { s });
}

fn pdf_string(text: &str) -> String {
    let mut s = String::from("(");
    for c in text.chars() {
        match winansi(c) {
            b'(' => s.push_str("\\("),
            b')' => s.push_str("\\)"),
            b'\\' => s.push_str("\\\\"),
            b @ 0x20..=0x7E => s.push(b as char),
            b => {
                let _ = write!(s, "\\{b:03o}");
            }
        }
    }
    s.push(')');
    s
}

/// Content stream drawing the image (centered, aspect kept) and then the text, on a canvas
/// of `cw` x `ch` points.
fn content(spec: &AppearanceSpec<'_>, cw: f32, ch: f32, image_size: Option<(u32, u32)>) -> String {
    let mut c = String::new();
    if let Some((iw, ih)) = image_size {
        let scale = (cw / iw as f32).min(ch / ih as f32);
        let (w, h) = (iw as f32 * scale, ih as f32 * scale);
        c.push_str("q ");
        for n in [w, 0.0, 0.0, h, (cw - w) / 2.0, (ch - h) / 2.0] {
            num(&mut c, n);
            c.push(' ');
        }
        c.push_str("cm /Im1 Do Q\n");
    }
    let Some(text) = spec.text.filter(|t| !t.is_empty()) else {
        return c;
    };
    let font = &spec.font;
    let (box_w, box_h) = (cw - 2.0 * MARGIN, ch - 2.0 * MARGIN);
    let layout = layout_text(font, text, box_w, box_h);
    let [r, g, b] = font.color;
    let _ = writeln!(c, "{r:.3} {g:.3} {b:.3} rg {r:.3} {g:.3} {b:.3} RG");
    let _ = writeln!(c, "BT /F1 {} Tf", {
        let mut s = String::new();
        num(&mut s, layout.size);
        s
    });
    let thickness = (layout.size / 20.0).max(0.1);
    let mut decorations = String::new();
    for (i, line) in layout.lines.iter().enumerate() {
        // The first baseline sits one font size below the top of the box.
        let y = ch - MARGIN - layout.size * (i + 1) as f32;
        let _ = writeln!(
            c,
            "1 0 0 1 {} {} Tm {} Tj",
            {
                let mut s = String::new();
                num(&mut s, MARGIN);
                s
            },
            {
                let mut s = String::new();
                num(&mut s, y);
                s
            },
            pdf_string(line)
        );
        if line.is_empty() {
            continue;
        }
        let w = font.text_width(line, layout.size);
        if font.underline {
            let uy = y - layout.size * 0.12;
            let _ = writeln!(
                decorations,
                "{} {} m {} {} l S",
                fmt(MARGIN),
                fmt(uy),
                fmt(MARGIN + w),
                fmt(uy)
            );
        }
        if font.strikethrough {
            let sy = y + layout.size * 0.3;
            let _ = writeln!(
                decorations,
                "{} {} m {} {} l S",
                fmt(MARGIN),
                fmt(sy),
                fmt(MARGIN + w),
                fmt(sy)
            );
        }
    }
    c.push_str("ET\n");
    if !decorations.is_empty() {
        let _ = writeln!(c, "{} w", fmt(thickness));
        c.push_str(&decorations);
    }
    c
}

fn fmt(n: f32) -> String {
    let mut s = String::new();
    num(&mut s, n);
    s
}

/// Builds the form XObject for `spec` and adds it to the update. Returns its object id.
pub fn add_appearance(
    w: &mut IncrementalWriter<'_>,
    spec: &AppearanceSpec<'_>,
) -> Result<ObjectId> {
    if !(spec.width > 0.0 && spec.height > 0.0) {
        return Err(Error::Other(
            "appearance needs a rectangle with area".into(),
        ));
    }
    let rotation = match spec.rotation {
        0 | 90 | 180 | 270 => spec.rotation,
        other => {
            return Err(options_err(format!(
                "visible.rotation {other}: expected 0, 90, 180 or 270"
            )));
        }
    };
    let (bw, bh) = (spec.width, spec.height);
    let (cw, ch) = if rotation % 180 == 0 {
        (bw, bh)
    } else {
        (bh, bw)
    };

    let mut resources = Dictionary::new();
    let mut fonts = Dictionary::new();
    let mut font = Dictionary::new();
    font.set("Type", Object::Name(b"Font".to_vec()));
    font.set("Subtype", Object::Name(b"Type1".to_vec()));
    font.set(
        "BaseFont",
        Object::Name(spec.font.base_font().as_bytes().to_vec()),
    );
    font.set("Encoding", Object::Name(b"WinAnsiEncoding".to_vec()));
    fonts.set("F1", Object::Dictionary(font));
    resources.set("Font", Object::Dictionary(fonts));

    let mut image_size = None;
    if let Some(bytes) = spec.image {
        let mut prepared = image::prepare(bytes)?;
        if let Some(mask) = prepared.mask.take() {
            let mask_id = w.add_object(Object::Stream(mask));
            prepared.image.dict.set("SMask", mask_id);
        }
        let image_id = w.add_object(Object::Stream(prepared.image));
        let mut xobjects = Dictionary::new();
        xobjects.set("Im1", image_id);
        resources.set("XObject", Object::Dictionary(xobjects));
        image_size = Some((prepared.width, prepared.height));
    }

    let mut body = content(spec, cw, ch, image_size);
    if rotation != 0 {
        let m = match rotation {
            90 => [0.0, 1.0, -1.0, 0.0, bw, 0.0],
            180 => [-1.0, 0.0, 0.0, -1.0, bw, bh],
            _ => [0.0, -1.0, 1.0, 0.0, 0.0, bh],
        };
        let mut head = String::from("q ");
        for n in m {
            head.push_str(&fmt(n));
            head.push(' ');
        }
        head.push_str("cm\n");
        body = format!("{head}{body}Q\n");
    }

    let mut dict = Dictionary::new();
    dict.set("Type", Object::Name(b"XObject".to_vec()));
    dict.set("Subtype", Object::Name(b"Form".to_vec()));
    dict.set("FormType", 1);
    dict.set(
        "BBox",
        vec![
            Object::Integer(0),
            Object::Integer(0),
            Object::Real(bw),
            Object::Real(bh),
        ],
    );
    dict.set("Resources", Object::Dictionary(resources));
    Ok(w.add_object(Object::Stream(Stream::new(dict, body.into_bytes()))))
}

/// Points the widget's normal appearance (`/AP /N`) at `form`.
pub fn set_widget_appearance(
    w: &mut IncrementalWriter<'_>,
    widget: ObjectId,
    form: ObjectId,
) -> Result<()> {
    let dict = w
        .modify(widget)?
        .as_dict_mut()
        .map_err(|_| Error::InvalidPdf("widget is not a dictionary".into()))?;
    let mut ap = Dictionary::new();
    ap.set("N", form);
    dict.set("AP", Object::Dictionary(ap));
    Ok(())
}
