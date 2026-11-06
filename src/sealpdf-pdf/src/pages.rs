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

/// Width, height and margin of the default signature box, in points.
const BOX_WIDTH: f32 = 200.0;
const BOX_HEIGHT: f32 = 50.0;
const BOX_MARGIN: f32 = 36.0;

/// Where a visible signature goes when the caller gives no place: the last page, in the lower-left
/// corner of the page as it is displayed.
///
/// Returns the 1-based page number and the rectangle in the page's default user space, the space
/// `/Rect` uses. The box is 200 x 50 points, 36 points from the left and bottom edges of the
/// crop box as displayed (`/Rotate` applied), and clipped when the page is too small for it.
pub fn default_signature_box(doc: &crate::PdfDocument) -> sealpdf_core::Result<(u32, [f32; 4])> {
    let page = doc.pages().last().ok_or(sealpdf_core::Error::Pdf(
        sealpdf_core::ErrorCode::INVALID_SIGNATURE_PAGE,
    ))?;
    Ok((page.number, default_box_on(page)))
}

fn default_box_on(page: &Page) -> [f32; 4] {
    let [x0, y0, x1, y1] = page.crop_box;
    let (w, h) = (x1 - x0, y1 - y0);
    let (dw, dh) = if page.rotation.is_multiple_of(180) {
        (w, h)
    } else {
        (h, w)
    };
    // The box in the displayed page, measured from its lower-left corner.
    let left = BOX_MARGIN.min(dw / 2.0);
    let bottom = BOX_MARGIN.min(dh / 2.0);
    let right = (left + BOX_WIDTH).min(dw);
    let top = (bottom + BOX_HEIGHT).min(dh);
    // Displayed point to user space, undoing the clockwise `/Rotate`.
    let to_user = |dx: f32, dy: f32| match page.rotation {
        90 => (x1 - dy, y0 + dx),
        180 => (x1 - dx, y1 - dy),
        270 => (x0 + dy, y1 - dx),
        _ => (x0 + dx, y0 + dy),
    };
    let (ax, ay) = to_user(left, bottom);
    let (bx, by) = to_user(right, top);
    normalize([ax, ay, bx, by])
}
