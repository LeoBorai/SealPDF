use lopdf::{Dictionary, Object, ObjectId, Stream, StringFormat};
use std::io::Write;

/// Writes `obj` in PDF syntax. Writing to a `Vec` cannot fail.
pub(crate) fn object(out: &mut Vec<u8>, obj: &Object) {
    match obj {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(true) => out.extend_from_slice(b"true"),
        Object::Boolean(false) => out.extend_from_slice(b"false"),
        Object::Integer(n) => {
            let _ = write!(out, "{n}");
        }
        Object::Real(r) => real(out, *r),
        Object::Name(n) => name(out, n),
        Object::String(s, StringFormat::Hexadecimal) => {
            out.push(b'<');
            for b in s {
                let _ = write!(out, "{b:02X}");
            }
            out.push(b'>');
        }
        Object::String(s, StringFormat::Literal) => literal(out, s),
        Object::Array(a) => {
            out.push(b'[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                object(out, item);
            }
            out.push(b']');
        }
        Object::Dictionary(d) => dictionary(out, d),
        Object::Stream(s) => stream(out, s),
        Object::Reference((n, g)) => {
            let _ = write!(out, "{n} {g} R");
        }
    }
}

fn real(out: &mut Vec<u8>, r: f32) {
    if !r.is_finite() {
        out.push(b'0');
        return;
    }
    let s = format!("{r:.6}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    out.extend_from_slice(if s.is_empty() || s == "-" {
        b"0"
    } else {
        s.as_bytes()
    });
}

fn name(out: &mut Vec<u8>, n: &[u8]) {
    out.push(b'/');
    for &b in n {
        let regular = b.is_ascii_graphic()
            && !matches!(
                b,
                b'#' | b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
            );
        if regular {
            out.push(b);
        } else {
            let _ = write!(out, "#{b:02X}");
        }
    }
}

fn literal(out: &mut Vec<u8>, s: &[u8]) {
    out.push(b'(');
    for &b in s {
        match b {
            b'(' | b')' | b'\\' => {
                out.push(b'\\');
                out.push(b);
            }
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            _ => out.push(b),
        }
    }
    out.push(b')');
}

pub(crate) fn dictionary(out: &mut Vec<u8>, d: &Dictionary) {
    out.extend_from_slice(b"<<");
    for (k, v) in d.iter() {
        name(out, k);
        // A name or string value needs no separator, but one keeps the output simple to read.
        out.push(b' ');
        object(out, v);
        out.push(b' ');
    }
    out.extend_from_slice(b">>");
}

fn stream(out: &mut Vec<u8>, s: &Stream) {
    let mut dict = s.dict.clone();
    dict.set("Length", s.content.len() as i64);
    dictionary(out, &dict);
    out.extend_from_slice(b"\nstream\n");
    out.extend_from_slice(&s.content);
    out.extend_from_slice(b"\nendstream");
}

/// `N G obj ... endobj`, returning the object's start offset relative to `out`'s start.
pub(crate) fn indirect(out: &mut Vec<u8>, id: ObjectId, obj: &Object) -> usize {
    let at = out.len();
    let _ = writeln!(out, "{} {} obj", id.0, id.1);
    object(out, obj);
    out.extend_from_slice(b"\nendobj\n");
    at
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::dictionary;

    fn s(obj: &Object) -> String {
        let mut v = Vec::new();
        object(&mut v, obj);
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn scalars() {
        assert_eq!(s(&Object::Null), "null");
        assert_eq!(s(&Object::Integer(-7)), "-7");
        assert_eq!(s(&Object::Real(1.5)), "1.5");
        assert_eq!(s(&Object::Real(2.0)), "2");
        assert_eq!(s(&Object::Real(-0.25)), "-0.25");
        assert_eq!(s(&Object::Reference((3, 0))), "3 0 R");
    }

    #[test]
    fn names_and_strings_are_escaped() {
        assert_eq!(s(&Object::Name(b"A B#".to_vec())), "/A#20B#23");
        assert_eq!(
            s(&Object::String(b"a(b)\\\n".to_vec(), StringFormat::Literal)),
            "(a\\(b\\)\\\\\\n)"
        );
        assert_eq!(
            s(&Object::String(vec![0xDE, 0xAD], StringFormat::Hexadecimal)),
            "<DEAD>"
        );
    }

    #[test]
    fn dictionaries_and_arrays() {
        let d = dictionary! { "A" => 1, "B" => vec![Object::Integer(1), Object::Null] };
        assert_eq!(s(&Object::Dictionary(d)), "<</A 1 /B [1 null] >>");
    }

    #[test]
    fn stream_gets_length() {
        let st = Stream::new(Dictionary::new(), b"hi".to_vec());
        assert!(s(&Object::Stream(st)).contains("/Length 2"));
    }
}
