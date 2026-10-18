use flate2::{Compression, write::ZlibEncoder};
use lopdf::{Dictionary, Object, Stream};
use sealpdf_core::{Error, Result};
use std::io::Write;

/// A decoded rubric image, ready to become image XObjects.
pub(crate) struct Prepared {
    pub width: u32,
    pub height: u32,
    pub image: Stream,
    /// Soft mask carrying the alpha channel, when the source had one.
    pub mask: Option<Stream>,
}

fn bad(msg: impl Into<String>) -> Error {
    Error::Other(format!("rubric image: {}", msg.into()))
}

pub(crate) fn prepare(bytes: &[u8]) -> Result<Prepared> {
    if bytes.starts_with(&[0xFF, 0xD8]) {
        jpeg(bytes)
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        decode_png(bytes)
    } else {
        Err(bad("only JPEG and PNG are supported"))
    }
}

fn image_dict(width: u32, height: u32, space: &str) -> Dictionary {
    let mut d = Dictionary::new();
    d.set("Type", Object::Name(b"XObject".to_vec()));
    d.set("Subtype", Object::Name(b"Image".to_vec()));
    d.set("Width", i64::from(width));
    d.set("Height", i64::from(height));
    d.set("ColorSpace", Object::Name(space.as_bytes().to_vec()));
    d.set("BitsPerComponent", 8);
    d
}

fn jpeg(bytes: &[u8]) -> Result<Prepared> {
    let mut i = 2;
    let mut adobe = false;
    while i + 4 <= bytes.len() {
        if bytes[i] != 0xFF {
            i += 1;
            continue;
        }
        let marker = bytes[i + 1];
        if marker == 0xFF {
            i += 1;
            continue;
        }
        if marker == 0xD8 || (0xD0..=0xD7).contains(&marker) || marker == 0x01 || marker == 0x00 {
            i += 2;
            continue;
        }
        let len = usize::from(u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]));
        let body = bytes
            .get(i + 4..i + 2 + len)
            .ok_or_else(|| bad("truncated JPEG"))?;
        if marker == 0xEE && body.starts_with(b"Adobe") {
            adobe = true;
        }
        let is_sof = (0xC0..=0xCF).contains(&marker) && !matches!(marker, 0xC4 | 0xC8 | 0xCC);
        if is_sof {
            if marker >= 0xC9 {
                return Err(bad("arithmetic-coded JPEG is not supported"));
            }
            if body.len() < 6 || body[0] != 8 {
                return Err(bad("only 8-bit JPEG is supported"));
            }
            let height = u32::from(u16::from_be_bytes([body[1], body[2]]));
            let width = u32::from(u16::from_be_bytes([body[3], body[4]]));
            let space = match body[5] {
                1 => "DeviceGray",
                3 => "DeviceRGB",
                4 => "DeviceCMYK",
                n => return Err(bad(format!("{n} JPEG components"))),
            };
            if width == 0 || height == 0 {
                return Err(bad("empty image"));
            }
            let mut dict = image_dict(width, height, space);
            dict.set("Filter", Object::Name(b"DCTDecode".to_vec()));
            if body[5] == 4 && adobe {
                // Adobe CMYK JPEGs store inverted values.
                dict.set(
                    "Decode",
                    [1, 0, 1, 0, 1, 0, 1, 0].map(Object::Integer).to_vec(),
                );
            }
            return Ok(Prepared {
                width,
                height,
                image: Stream::new(dict, bytes.to_vec()),
                mask: None,
            });
        }
        i += 2 + len;
    }
    Err(bad("no frame header found in JPEG"))
}

fn deflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).map_err(|e| bad(e.to_string()))?;
    enc.finish().map_err(|e| bad(e.to_string()))
}

fn flate_stream(mut dict: Dictionary, raw: &[u8]) -> Result<Stream> {
    dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));
    Ok(Stream::new(dict, deflate(raw)?))
}

fn decode_png(bytes: &[u8]) -> Result<Prepared> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().map_err(|e| bad(e.to_string()))?;
    let mut buf = vec![
        0;
        reader
            .output_buffer_size()
            .ok_or_else(|| bad("image too large"))?
    ];
    let info = reader
        .next_frame(&mut buf)
        .map_err(|e| bad(e.to_string()))?;
    buf.truncate(info.buffer_size());
    let (width, height) = (info.width, info.height);
    if width == 0 || height == 0 {
        return Err(bad("empty image"));
    }

    let (space, color, alpha): (&str, Vec<u8>, Option<Vec<u8>>) = match info.color_type {
        png::ColorType::Grayscale => ("DeviceGray", buf, None),
        png::ColorType::Rgb => ("DeviceRGB", buf, None),
        png::ColorType::GrayscaleAlpha => (
            "DeviceGray",
            buf.as_chunks::<2>().0.iter().map(|p| p[0]).collect(),
            Some(buf.as_chunks::<2>().0.iter().map(|p| p[1]).collect()),
        ),
        png::ColorType::Rgba => (
            "DeviceRGB",
            buf.as_chunks::<4>()
                .0
                .iter()
                .flat_map(|p| [p[0], p[1], p[2]])
                .collect(),
            Some(buf.as_chunks::<4>().0.iter().map(|p| p[3]).collect()),
        ),
        png::ColorType::Indexed => return Err(bad("indexed PNG was not expanded")),
    };
    let image = flate_stream(image_dict(width, height, space), &color)?;
    let mask = alpha
        .map(|a| flate_stream(image_dict(width, height, "DeviceGray"), &a))
        .transpose()?;
    Ok(Prepared {
        width,
        height,
        image,
        mask,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_bytes(color: png::ColorType, data: &[u8], w: u32, h: u32) -> Vec<u8> {
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
    fn png_rgb_has_no_mask() {
        let p = prepare(&png_bytes(
            png::ColorType::Rgb,
            &[255, 0, 0, 0, 255, 0],
            2,
            1,
        ))
        .unwrap();
        assert_eq!((p.width, p.height), (2, 1));
        assert!(p.mask.is_none());
        assert_eq!(
            p.image.dict.get(b"ColorSpace").unwrap().as_name().unwrap(),
            b"DeviceRGB"
        );
        assert_eq!(
            p.image.dict.get(b"Filter").unwrap().as_name().unwrap(),
            b"FlateDecode"
        );
    }

    #[test]
    fn png_alpha_becomes_soft_mask() {
        let p = prepare(&png_bytes(
            png::ColorType::Rgba,
            &[1, 2, 3, 128, 4, 5, 6, 255],
            2,
            1,
        ))
        .unwrap();
        let mask = p.mask.expect("soft mask");
        assert_eq!(
            mask.dict.get(b"ColorSpace").unwrap().as_name().unwrap(),
            b"DeviceGray"
        );
        assert_eq!(
            p.image.dict.get(b"ColorSpace").unwrap().as_name().unwrap(),
            b"DeviceRGB"
        );
    }

    #[test]
    fn png_gray_alpha() {
        let p = prepare(&png_bytes(
            png::ColorType::GrayscaleAlpha,
            &[10, 20, 30, 40],
            2,
            1,
        ))
        .unwrap();
        assert!(p.mask.is_some());
        assert_eq!(
            p.image.dict.get(b"ColorSpace").unwrap().as_name().unwrap(),
            b"DeviceGray"
        );
    }

    #[test]
    fn jpeg_header_is_read_without_decoding() {
        // SOI, APP0 stub, SOF0 (8-bit, 20 high, 10 wide, 3 components), EOI.
        let mut j = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00];
        j.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 8, 0, 20, 0, 10, 3]);
        j.extend_from_slice(&[1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
        j.extend_from_slice(&[0xFF, 0xD9]);
        let p = prepare(&j).unwrap();
        assert_eq!((p.width, p.height), (10, 20));
        assert_eq!(
            p.image.dict.get(b"Filter").unwrap().as_name().unwrap(),
            b"DCTDecode"
        );
        assert_eq!(p.image.content, j, "JPEG data passes through untouched");
    }

    #[test]
    fn rejects_other_formats() {
        assert!(prepare(b"GIF89a....").is_err());
        assert!(prepare(&[0xFF, 0xD8, 0xFF, 0xD9]).is_err());
    }
}
