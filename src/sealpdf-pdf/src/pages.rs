use lopdf::{Dictionary, Document, Object, ObjectId};

#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    /// 1-based position in the page tree.
    pub number: u32,
    pub id: ObjectId,
    pub media_box: [f32; 4],
    pub crop_box: [f32; 4],
    /// Normalized to 0, 90, 180 or 270.
    pub rotation: u32,
}

const MAX_PARENT_DEPTH: usize = 64;

/// Looks up a page attribute, following `/Parent` for inheritable ones.
pub(crate) fn inherited<'a>(doc: &'a Document, page: ObjectId, key: &[u8]) -> Option<&'a Object> {
    let mut id = page;
    for _ in 0..MAX_PARENT_DEPTH {
        let dict = doc.get_dictionary(id).ok()?;
        if let Ok(obj) = dict.get(key) {
            return doc.dereference(obj).ok().map(|(_, o)| o);
        }
        id = dict.get(b"Parent").ok()?.as_reference().ok()?;
    }
    None
}

pub(crate) fn rect(doc: &Document, obj: &Object) -> Option<[f32; 4]> {
    let (_, obj) = doc.dereference(obj).ok()?;
    let arr = obj.as_array().ok()?;
    if arr.len() != 4 {
        return None;
    }
    let mut out = [0f32; 4];
    for (slot, item) in out.iter_mut().zip(arr) {
        *slot = doc.dereference(item).ok()?.1.as_float().ok()?;
    }
    Some(out)
}

/// Normalizes a rectangle so that `[llx, lly, urx, ury]` holds whatever corner order the file used.
pub(crate) fn normalize(r: [f32; 4]) -> [f32; 4] {
    [
        r[0].min(r[2]),
        r[1].min(r[3]),
        r[0].max(r[2]),
        r[1].max(r[3]),
    ]
}

pub(crate) fn read_pages(doc: &Document) -> Vec<Page> {
    doc.get_pages()
        .into_iter()
        .map(|(number, id)| {
            let media_box = inherited(doc, id, b"MediaBox")
                .and_then(|o| rect(doc, o))
                .map(normalize)
                .unwrap_or([0.0, 0.0, 612.0, 792.0]);
            let crop_box = inherited(doc, id, b"CropBox")
                .and_then(|o| rect(doc, o))
                .map(normalize)
                .unwrap_or(media_box);
            let rotation = inherited(doc, id, b"Rotate")
                .and_then(|o| o.as_i64().ok())
                .map_or(0, |r| r.rem_euclid(360) as u32);
            Page {
                number,
                id,
                media_box,
                crop_box,
                rotation,
            }
        })
        .collect()
}

pub(crate) fn name_of(dict: &Dictionary, key: &[u8]) -> Option<String> {
    dict.get(key)
        .ok()?
        .as_name()
        .ok()
        .map(|n| String::from_utf8_lossy(n).into_owned())
}
