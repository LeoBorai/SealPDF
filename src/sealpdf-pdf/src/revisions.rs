/// A revision of the file: the bytes `0..end` form a complete, parseable PDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revision {
    /// Offset just past the `%%EOF` marker that closes the revision.
    pub end: usize,
    /// Offset of the revision's cross-reference section (the `startxref` value).
    /// Zero when the file has no valid trailer.
    pub xref_offset: usize,
    /// The cross-reference section is a stream, not a classic `xref` table.
    pub xref_stream: bool,
}

const EOF: &[u8] = b"%%EOF";
const STARTXREF: &[u8] = b"startxref";

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' | 0)
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
    {
        out.push(from + pos);
        from += pos + needle.len();
    }
    out
}

/// Finds the revisions of a PDF by looking for `startxref <offset> %%EOF` trailers.
///
/// A trailer counts only when its offset points at an `xref` table or an
/// `N G obj` header, which discards false hits in stream data and the
/// `startxref 0` trailer of a linearized file's first-page section.
/// A file without any valid trailer is one revision covering the whole file.
pub fn scan(bytes: &[u8]) -> Vec<Revision> {
    let mut revisions = Vec::new();
    for at in find_all(bytes, STARTXREF) {
        let mut i = at + STARTXREF.len();
        while i < bytes.len() && is_ws(bytes[i]) {
            i += 1;
        }
        let digits = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == digits {
            continue;
        }
        let Some(offset) = std::str::from_utf8(&bytes[digits..i])
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
        else {
            continue;
        };
        while i < bytes.len() && is_ws(bytes[i]) {
            i += 1;
        }
        if !bytes[i..].starts_with(EOF) {
            continue;
        }
        let Some(xref_stream) = xref_kind(bytes, offset) else {
            continue;
        };
        revisions.push(Revision {
            end: i + EOF.len(),
            xref_offset: offset,
            xref_stream,
        });
    }
    if revisions.is_empty() {
        revisions.push(Revision {
            end: bytes.len(),
            xref_offset: 0,
            xref_stream: false,
        });
    }
    revisions
}

/// `Some(false)` for a classic table, `Some(true)` for a stream, `None` when `offset` is neither.
fn xref_kind(bytes: &[u8], offset: usize) -> Option<bool> {
    let rest = bytes.get(offset..)?;
    if rest.starts_with(b"xref") {
        return Some(false);
    }
    // Cross-reference stream: `N G obj`.
    let head = &rest[..rest.len().min(40)];
    let mut parts = head.split(|&b| is_ws(b)).filter(|p| !p.is_empty());
    let num = |p: Option<&[u8]>| p.is_some_and(|p| p.iter().all(u8::is_ascii_digit));
    (num(parts.next()) && num(parts.next()) && parts.next().is_some_and(|p| p.starts_with(b"obj")))
        .then_some(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_classic_revisions() {
        let first = "%PDF-1.4\n1 0 obj<<>>endobj\nxref\n0 1\ntrailer<<>>\n";
        let xref1 = first.find("xref").unwrap();
        let mut pdf = format!("{first}startxref\n{xref1}\n%%EOF\n");
        let xref2 = pdf.len() + "2 0 obj<<>>endobj\n".len();
        pdf.push_str(&format!(
            "2 0 obj<<>>endobj\nxref\n0 1\ntrailer<<>>\nstartxref\n{xref2}\n%%EOF\n"
        ));
        let r = scan(pdf.as_bytes());
        assert_eq!(r.len(), 2);
        assert!(r[0].end < r[1].end);
        assert!(!r[0].xref_stream && r[0].xref_offset == xref1);
        assert_eq!(r[1].xref_offset, xref2);
        assert_eq!(&pdf.as_bytes()[r[0].end - 5..r[0].end], b"%%EOF");
    }

    #[test]
    fn counts_xref_stream_revision() {
        let pdf = b"%PDF-1.5\n7 0 obj<</Type/XRef>>stream\nendstream endobj\nstartxref\n9\n%%EOF";
        let r = scan(pdf);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].end, pdf.len());
        assert!(r[0].xref_stream);
    }

    #[test]
    fn ignores_linearized_first_page_trailer_and_fake_hits() {
        let pdf = b"%PDF-1.4\n1 0 obj<<>>endobj\nxref\n0 1\ntrailer<<>>\nstartxref\n0\n%%EOF\n\
                    (startxref 9999 %%EOF)\nxref\n0 1\ntrailer<<>>\nstartxref\n29\n%%EOF";
        // `startxref 0` points at the header, 9999 is out of range.
        assert_eq!(scan(pdf).len(), 1);
    }

    #[test]
    fn no_trailer_is_one_revision() {
        assert_eq!(
            scan(b"%PDF-1.4 garbage"),
            vec![Revision {
                end: 16,
                xref_offset: 0,
                xref_stream: false
            }]
        );
    }
}
