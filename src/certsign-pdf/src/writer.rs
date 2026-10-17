use crate::{PdfDocument, serialize};
use certsign_core::{Error, Result};
use lopdf::{Dictionary, Object, ObjectId, Stream, StringFormat};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write};

/// Placeholder for the three `/ByteRange` numbers; patched in place once layout is known.
const BYTE_RANGE_PLACEHOLDER: &str = "[0 9999999999 9999999999 9999999999]";
const NUMBER_WIDTH: usize = 10;

/// Offsets of the `<` and `>` that delimit the `/Contents` hex string.
type ContentsSpan = (usize, usize);

/// Appends new and changed objects to a PDF as one incremental update.
///
/// The original bytes are never touched. The update ends with a cross-reference
/// section of the same kind (classic table or stream) as the previous revision.
pub struct IncrementalWriter<'a> {
    pdf: &'a PdfDocument,
    objects: BTreeMap<u32, (u16, Object)>,
    next_id: u32,
    signature: Option<(ObjectId, usize)>,
}

impl<'a> IncrementalWriter<'a> {
    pub fn new(pdf: &'a PdfDocument) -> Result<Self> {
        if pdf.is_encrypted() {
            return Err(Error::Other(
                "incremental updates of encrypted PDFs are not supported yet".into(),
            ));
        }
        if pdf.revisions().last().is_none_or(|r| r.xref_offset == 0) {
            return Err(Error::InvalidPdf("no valid startxref to append to".into()));
        }
        let doc = pdf.document();
        let size = doc
            .trailer
            .get(b"Size")
            .ok()
            .and_then(|o| o.as_i64().ok())
            .unwrap_or(0)
            .max(0) as u32;
        Ok(Self {
            pdf,
            objects: BTreeMap::new(),
            next_id: doc.max_id.max(size.saturating_sub(1)) + 1,
            signature: None,
        })
    }

    /// The document this update is appended to.
    pub fn pdf(&self) -> &'a PdfDocument {
        self.pdf
    }

    pub fn new_object_id(&mut self) -> ObjectId {
        let id = (self.next_id, 0);
        self.next_id += 1;
        id
    }

    pub fn add_object(&mut self, obj: impl Into<Object>) -> ObjectId {
        let id = self.new_object_id();
        self.objects.insert(id.0, (0, obj.into()));
        id
    }

    /// Replaces an object (new or existing) with `obj`.
    pub fn set_object(&mut self, id: ObjectId, obj: impl Into<Object>) {
        self.objects.insert(id.0, (id.1, obj.into()));
    }

    /// The current version of an object: this update's, else the previous revision's.
    pub fn get(&self, id: ObjectId) -> Option<&Object> {
        match self.objects.get(&id.0) {
            Some((_, obj)) => Some(obj),
            None => self.pdf.document().get_object(id).ok(),
        }
    }

    /// Mutable access to an object, copying it into this update first when it is from an earlier revision.
    pub fn modify(&mut self, id: ObjectId) -> Result<&mut Object> {
        if !self.objects.contains_key(&id.0) {
            let existing = self
                .pdf
                .document()
                .get_object(id)
                .map_err(|e| Error::InvalidPdf(format!("object {} {} R: {e}", id.0, id.1)))?
                .clone();
            self.objects.insert(id.0, (id.1, existing));
        }
        Ok(&mut self.objects.get_mut(&id.0).expect("just inserted").1)
    }

    /// Adds the signature dictionary with `/ByteRange` and `/Contents` placeholders.
    ///
    /// `reserved` is the capacity of `/Contents` in bytes. Only one signature per update.
    pub fn add_signature(&mut self, mut dict: Dictionary, reserved: usize) -> Result<ObjectId> {
        if self.signature.is_some() {
            return Err(Error::Other("only one signature per update".into()));
        }
        let range = vec![
            Object::Integer(0),
            Object::Integer(9_999_999_999),
            Object::Integer(9_999_999_999),
            Object::Integer(9_999_999_999),
        ];
        dict.set("ByteRange", Object::Array(range));
        dict.set(
            "Contents",
            Object::String(vec![0; reserved], StringFormat::Hexadecimal),
        );
        let id = self.add_object(Object::Dictionary(dict));
        self.signature = Some((id, reserved));
        Ok(id)
    }

    /// Finishes an update that has no signature placeholder.
    pub fn finish(self) -> Result<Vec<u8>> {
        if self.signature.is_some() {
            return Err(Error::Other(
                "update has a signature placeholder: use finish_signature".into(),
            ));
        }
        Ok(self.write()?.0)
    }

    /// Finishes an update that has a signature placeholder.
    pub fn finish_signature(self) -> Result<PreparedSignature> {
        if self.signature.is_none() {
            return Err(Error::Other("update has no signature placeholder".into()));
        }
        let (bytes, layout) = self.write()?;
        let (lt, gt) = layout.expect("signature layout");
        Ok(PreparedSignature { bytes, lt, gt })
    }

    fn write(mut self) -> Result<(Vec<u8>, Option<ContentsSpan>)> {
        let original = self.pdf.bytes();
        let mut out = original.to_vec();
        if !matches!(out.last(), Some(b'\n' | b'\r')) {
            out.push(b'\n');
        }

        let mut offsets: Vec<(u32, u16, usize)> = Vec::new();
        let mut layout = None;
        for (id, (gen_, obj)) in &self.objects {
            let at = serialize::indirect(&mut out, (*id, *gen_), obj);
            offsets.push((*id, *gen_, at));
            if self.signature.is_some_and(|(sig, _)| sig.0 == *id) {
                layout = Some(locate_placeholders(&out, at, self.signature.unwrap().1)?);
            }
        }

        let trailer = self.trailer_entries(&out[original.len()..]);
        let prev = self
            .pdf
            .revisions()
            .last()
            .map(|r| r.xref_offset)
            .unwrap_or_default();
        let use_stream = self.pdf.revisions().last().is_some_and(|r| r.xref_stream);

        if use_stream {
            let xref_id = self.new_object_id();
            let at = out.len();
            offsets.push((xref_id.0, 0, at));
            let (dict, data) = xref_stream_parts(&offsets, trailer, prev, self.next_id)?;
            let obj = Object::Stream(Stream::new(dict, data));
            serialize::indirect(&mut out, xref_id, &obj);
            let _ = write!(out, "startxref\n{at}\n%%EOF\n");
        } else {
            let at = out.len();
            write_xref_table(&mut out, &offsets);
            let mut dict = trailer;
            dict.set("Size", i64::from(self.next_id));
            dict.set("Prev", prev as i64);
            out.extend_from_slice(b"trailer\n");
            serialize::dictionary(&mut out, &dict);
            let _ = write!(out, "\nstartxref\n{at}\n%%EOF\n");
        }

        if let Some((lt, gt)) = layout {
            patch_byte_range(&mut out, lt, gt)?;
        }
        Ok((out, layout))
    }

    /// `/Root`, `/Info` and `/ID` for the new trailer. The first ID is kept, the second renewed.
    fn trailer_entries(&self, appended: &[u8]) -> Dictionary {
        let prev = &self.pdf.document().trailer;
        let mut dict = Dictionary::new();
        for key in [&b"Root"[..], b"Info"] {
            if let Ok(v) = prev.get(key) {
                dict.set(key.to_vec(), v.clone());
            }
        }
        let mut hasher = Sha256::new();
        hasher.update(self.pdf.bytes());
        hasher.update(appended);
        let fresh = hasher.finalize()[..16].to_vec();
        let first = prev
            .get(b"ID")
            .ok()
            .and_then(|o| o.as_array().ok())
            .and_then(|a| a.first())
            .and_then(|o| o.as_str().ok())
            .map_or_else(|| fresh.clone(), <[u8]>::to_vec);
        dict.set(
            "ID",
            vec![
                Object::String(first, StringFormat::Hexadecimal),
                Object::String(fresh, StringFormat::Hexadecimal),
            ],
        );
        dict
    }
}

/// Finds the placeholders of the signature object written at `at`. Returns the `<` and `>` of `/Contents`.
fn locate_placeholders(out: &[u8], at: usize, reserved: usize) -> Result<ContentsSpan> {
    let find = |needle: &[u8]| {
        out[at..]
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|p| at + p)
    };
    let missing = || Error::Other("signature placeholders not found".into());
    let br = find(BYTE_RANGE_PLACEHOLDER.as_bytes()).ok_or_else(missing)?;
    debug_assert!(br > at);
    let contents = find(b"/Contents ").ok_or_else(missing)?;
    let lt = contents + b"/Contents ".len();
    let gt = lt + 1 + 2 * reserved;
    if out.get(lt) != Some(&b'<') || out.get(gt) != Some(&b'>') {
        return Err(missing());
    }
    Ok((lt, gt))
}

fn patch_byte_range(out: &mut [u8], lt: usize, gt: usize) -> Result<()> {
    let total = out.len();
    let range = [0, lt, gt + 1, total - (gt + 1)];
    if range.iter().any(|n| n.to_string().len() > NUMBER_WIDTH) {
        return Err(Error::Other("file too large for /ByteRange".into()));
    }
    let text = format!(
        "[0 {:<w$} {:<w$} {:<w$}]",
        range[1],
        range[2],
        range[3],
        w = NUMBER_WIDTH
    );
    debug_assert_eq!(text.len(), BYTE_RANGE_PLACEHOLDER.len());
    let at = out
        .windows(BYTE_RANGE_PLACEHOLDER.len())
        .rposition(|w| w == BYTE_RANGE_PLACEHOLDER.as_bytes())
        .ok_or_else(|| Error::Other("signature placeholders not found".into()))?;
    out[at..at + text.len()].copy_from_slice(text.as_bytes());
    Ok(())
}

/// Groups sorted object ids into runs of consecutive numbers: `(first id, entries)`.
fn runs(offsets: &[(u32, u16, usize)]) -> Vec<(u32, Vec<(u16, usize)>)> {
    let mut sorted = offsets.to_vec();
    sorted.sort_by_key(|e| e.0);
    let mut out: Vec<(u32, Vec<(u16, usize)>)> = Vec::new();
    for (id, gen_, at) in sorted {
        match out.last_mut() {
            Some((start, entries)) if *start + entries.len() as u32 == id => {
                entries.push((gen_, at));
            }
            _ => out.push((id, vec![(gen_, at)])),
        }
    }
    out
}

fn write_xref_table(out: &mut Vec<u8>, offsets: &[(u32, u16, usize)]) {
    out.extend_from_slice(b"xref\n");
    for (start, entries) in runs(offsets) {
        let _ = writeln!(out, "{start} {}", entries.len());
        for (gen_, at) in entries {
            // Entries are exactly 20 bytes: the line end is a space and a line feed.
            let _ = writeln!(out, "{at:010} {gen_:05} n ");
        }
    }
}

fn xref_stream_parts(
    offsets: &[(u32, u16, usize)],
    mut dict: Dictionary,
    prev: usize,
    size: u32,
) -> Result<(Dictionary, Vec<u8>)> {
    let mut index = Vec::new();
    let mut data = Vec::new();
    for (start, entries) in runs(offsets) {
        index.push(Object::Integer(i64::from(start)));
        index.push(Object::Integer(entries.len() as i64));
        for (gen_, at) in entries {
            let at = u32::try_from(at)
                .map_err(|_| Error::Other("file too large for the xref stream".into()))?;
            data.push(1);
            data.extend_from_slice(&at.to_be_bytes());
            data.extend_from_slice(&gen_.to_be_bytes());
        }
    }
    dict.set("Type", Object::Name(b"XRef".to_vec()));
    dict.set("Size", i64::from(size));
    dict.set(
        "W",
        vec![Object::Integer(1), Object::Integer(4), Object::Integer(2)],
    );
    dict.set("Index", Object::Array(index));
    dict.set("Prev", prev as i64);
    Ok((dict, data))
}

/// An update whose signature is not yet embedded.
#[derive(Debug)]
pub struct PreparedSignature {
    bytes: Vec<u8>,
    lt: usize,
    gt: usize,
}

impl PreparedSignature {
    /// `[0, a, b, c]`: the file minus the `/Contents` value, delimiters included.
    pub fn byte_range(&self) -> [usize; 4] {
        [0, self.lt, self.gt + 1, self.bytes.len() - (self.gt + 1)]
    }

    /// The bytes covered by the signature, in order.
    pub fn signed_parts(&self) -> [&[u8]; 2] {
        [&self.bytes[..self.lt], &self.bytes[self.gt + 1..]]
    }

    /// Largest signature, in bytes, that fits in `/Contents`.
    pub fn capacity(&self) -> usize {
        (self.gt - self.lt - 1) / 2
    }

    /// Writes `signature` (a DER CMS) into `/Contents`, zero padded.
    pub fn embed(mut self, signature: &[u8]) -> Result<Vec<u8>> {
        if signature.len() > self.capacity() {
            return Err(Error::SignatureTooLarge {
                needed: signature.len(),
                reserved: self.capacity(),
            });
        }
        let mut at = self.lt + 1;
        for b in signature {
            let hex = format!("{b:02X}");
            self.bytes[at..at + 2].copy_from_slice(hex.as_bytes());
            at += 2;
        }
        Ok(self.bytes)
    }
}
