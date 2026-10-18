use crate::{IncrementalWriter, Page, fields};
use certsign_core::{Error, ErrorCode, Page as PageChoice, Result};
use lopdf::{Dictionary, Object, ObjectId, StringFormat};

/// Where the signature goes.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldTarget<'a> {
    /// A new field named `SignatureN`. No rectangle makes it invisible.
    ///
    /// A rectangle with no area, or one completely outside the page, is an
    /// `INVALID_SIGNATURE_POSITION` error. One that only overhangs the page is clipped to it.
    /// `Page::Append` adds a blank page, sized like page one, at the end of the document.
    New {
        page: PageChoice,
        rect: Option<[f32; 4]>,
    },
    /// An existing, unsigned signature field.
    Existing { name: &'a str },
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttachedField {
    pub name: String,
    /// The field dictionary that now holds `/V`.
    pub field_id: ObjectId,
    /// The widget annotation (the same object as the field when they are merged).
    pub widget_id: ObjectId,
    pub page: Option<u32>,
    /// `[0 0 0 0]` for invisible signatures.
    pub rect: [f32; 4],
    /// The field was created by this update.
    pub created: bool,
}

impl AttachedField {
    pub fn is_visible(&self) -> bool {
        self.rect[2] > self.rect[0] && self.rect[3] > self.rect[1]
    }
}

/// Anchors the signature dictionary `sig` in the form: creates the field, widget and
/// `/Annots` entry, or fills an existing empty field. Sets `/SigFlags` to include 3.
pub fn attach_signature(
    w: &mut IncrementalWriter<'_>,
    target: &FieldTarget<'_>,
    sig: ObjectId,
) -> Result<AttachedField> {
    match target {
        FieldTarget::New { page, rect } => create(w, *page, *rect, sig),
        FieldTarget::Existing { name } => fill(w, name, sig),
    }
}

fn fill(w: &mut IncrementalWriter<'_>, name: &str, sig: ObjectId) -> Result<AttachedField> {
    let pdf = w.pdf();
    let field = pdf
        .signature_fields()
        .into_iter()
        .find(|f| f.name == name)
        .ok_or_else(|| Error::SignatureField(format!("no signature field named {name:?}")))?;
    if field.is_signed() {
        return Err(Error::SignatureField(format!(
            "field {name:?} is already signed"
        )));
    }
    w.modify(field.id)?
        .as_dict_mut()
        .map_err(|_| Error::SignatureField(format!("field {name:?} is not a dictionary")))?
        .set("V", sig);
    ensure_sig_flags(w)?;
    Ok(AttachedField {
        name: field.name,
        field_id: field.id,
        widget_id: field.widget_id,
        page: field.page,
        rect: field.rect.unwrap_or([0.0; 4]),
        created: false,
    })
}

fn create(
    w: &mut IncrementalWriter<'_>,
    page: PageChoice,
    rect: Option<[f32; 4]>,
    sig: ObjectId,
) -> Result<AttachedField> {
    let invalid_page = || Error::Pdf(ErrorCode::INVALID_SIGNATURE_PAGE);
    let count = w.pdf().pages().len() as u32;
    // Decide the page and check the rectangle before changing anything.
    let (page_number, existing) = match page {
        PageChoice::Number(n) if (1..=count).contains(&n) => (n, true),
        PageChoice::Number(_) => return Err(invalid_page()),
        PageChoice::Last if count > 0 => (count, true),
        PageChoice::Last => return Err(invalid_page()),
        PageChoice::Append => (count + 1, false),
    };
    let first = w.pdf().page(1).ok_or_else(invalid_page)?;
    let page_box = if existing {
        sized_box(w.pdf().page(page_number).ok_or_else(invalid_page)?)
    } else {
        sized_box(first)
    };
    let rect = rect.map(|r| place_rect(r, page_box)).transpose()?;
    let page_id = if existing {
        w.pdf().page(page_number).ok_or_else(invalid_page)?.id
    } else {
        append_page(w, first)?
    };
    let taken = fields::all_field_names(w.pdf().document());
    let name = (1..)
        .map(|n| format!("Signature{n}"))
        .find(|n| !taken.contains(n))
        .expect("unbounded range");
    let rect = rect.unwrap_or([0.0; 4]);

    let mut widget = Dictionary::new();
    widget.set("Type", Object::Name(b"Annot".to_vec()));
    widget.set("Subtype", Object::Name(b"Widget".to_vec()));
    widget.set("FT", Object::Name(b"Sig".to_vec()));
    widget.set(
        "T",
        Object::String(name.clone().into_bytes(), StringFormat::Literal),
    );
    widget.set("F", 132); // print + locked
    widget.set(
        "Rect",
        rect.iter().map(|n| Object::Real(*n)).collect::<Vec<_>>(),
    );
    widget.set("P", page_id);
    widget.set("V", sig);
    let widget_id = w.add_object(Object::Dictionary(widget));

    push_annot(w, page_id, widget_id)?;
    push_field(w, widget_id)?;
    ensure_sig_flags(w)?;
    Ok(AttachedField {
        name,
        field_id: widget_id,
        widget_id,
        page: Some(page_number),
        rect,
        created: true,
    })
}

fn bad(what: &str) -> Error {
    Error::InvalidPdf(what.to_owned())
}

/// Appends `item` to the array stored under `key` in the dictionary at `owner`, whether the
/// array is direct or an indirect object, creating it when absent.
fn push_to_array(
    w: &mut IncrementalWriter<'_>,
    owner: ObjectId,
    key: &[u8],
    item: ObjectId,
) -> Result<()> {
    let indirect = match w.get(owner).and_then(|o| o.as_dict().ok()) {
        Some(d) => match d.get(key) {
            Ok(Object::Reference(r)) => Some(*r),
            _ => None,
        },
        None => return Err(bad("signature container is not a dictionary")),
    };
    if let Some(array_id) = indirect {
        match w.modify(array_id)? {
            Object::Array(a) => a.push(Object::Reference(item)),
            _ => return Err(bad("expected an array")),
        }
        return Ok(());
    }
    let dict = w
        .modify(owner)?
        .as_dict_mut()
        .map_err(|_| bad("expected a dictionary"))?;
    match dict.get_mut(key) {
        Ok(Object::Array(a)) => a.push(Object::Reference(item)),
        Ok(_) => return Err(bad("expected an array")),
        Err(_) => dict.set(key.to_vec(), vec![Object::Reference(item)]),
    }
    Ok(())
}

fn push_annot(w: &mut IncrementalWriter<'_>, page: ObjectId, widget: ObjectId) -> Result<()> {
    push_to_array(w, page, b"Annots", widget)
}

fn catalog_id(w: &IncrementalWriter<'_>) -> Result<ObjectId> {
    w.pdf()
        .document()
        .trailer
        .get(b"Root")
        .ok()
        .and_then(|o| o.as_reference().ok())
        .ok_or_else(|| bad("missing /Root"))
}

/// Where the AcroForm dictionary lives.
enum Form {
    Indirect(ObjectId),
    InCatalog(ObjectId),
    Missing,
}

fn form_location(w: &IncrementalWriter<'_>) -> Result<Form> {
    let catalog = catalog_id(w)?;
    let dict = w
        .get(catalog)
        .and_then(|o| o.as_dict().ok())
        .ok_or_else(|| bad("catalog is not a dictionary"))?;
    Ok(match dict.get(b"AcroForm") {
        Ok(Object::Reference(r)) => Form::Indirect(*r),
        Ok(Object::Dictionary(_)) => Form::InCatalog(catalog),
        _ => Form::Missing,
    })
}

fn push_field(w: &mut IncrementalWriter<'_>, widget: ObjectId) -> Result<()> {
    match form_location(w)? {
        Form::Indirect(form) => push_to_array(w, form, b"Fields", widget),
        Form::InCatalog(catalog) => {
            // The form dictionary is a direct value inside the catalog.
            let fields_ref = w
                .get(catalog)
                .and_then(|o| o.as_dict().ok())
                .and_then(|c| c.get(b"AcroForm").ok())
                .and_then(|f| f.as_dict().ok())
                .and_then(|f| match f.get(b"Fields") {
                    Ok(Object::Reference(r)) => Some(*r),
                    _ => None,
                });
            if let Some(array_id) = fields_ref {
                return match w.modify(array_id)? {
                    Object::Array(a) => {
                        a.push(Object::Reference(widget));
                        Ok(())
                    }
                    _ => Err(bad("/Fields is not an array")),
                };
            }
            let form = w
                .modify(catalog)?
                .as_dict_mut()
                .ok()
                .and_then(|c| c.get_mut(b"AcroForm").ok())
                .and_then(|f| f.as_dict_mut().ok())
                .ok_or_else(|| bad("AcroForm is not a dictionary"))?;
            match form.get_mut(b"Fields") {
                Ok(Object::Array(a)) => a.push(Object::Reference(widget)),
                Ok(_) => return Err(bad("/Fields is not an array")),
                Err(_) => form.set("Fields", vec![Object::Reference(widget)]),
            }
            Ok(())
        }
        Form::Missing => {
            let mut form = Dictionary::new();
            form.set("Fields", vec![Object::Reference(widget)]);
            form.set("SigFlags", 3);
            let form_id = w.add_object(Object::Dictionary(form));
            let catalog = catalog_id(w)?;
            w.modify(catalog)?
                .as_dict_mut()
                .map_err(|_| bad("catalog is not a dictionary"))?
                .set("AcroForm", form_id);
            Ok(())
        }
    }
}

/// Makes sure `/SigFlags` has both bits set (signatures exist, append only).
fn ensure_sig_flags(w: &mut IncrementalWriter<'_>) -> Result<()> {
    let current = |form: &Dictionary| {
        form.get(b"SigFlags")
            .ok()
            .and_then(|o| o.as_i64().ok())
            .unwrap_or(0)
    };
    match form_location(w)? {
        Form::Missing => Ok(()), // created with flags 3 by `push_field`
        Form::Indirect(id) => {
            let have = w.get(id).and_then(|o| o.as_dict().ok()).map_or(0, current);
            if have & 3 != 3 {
                w.modify(id)?
                    .as_dict_mut()
                    .map_err(|_| bad("AcroForm is not a dictionary"))?
                    .set("SigFlags", have | 3);
            }
            Ok(())
        }
        Form::InCatalog(catalog) => {
            let have = w
                .get(catalog)
                .and_then(|o| o.as_dict().ok())
                .and_then(|c| c.get(b"AcroForm").ok())
                .and_then(|f| f.as_dict().ok())
                .map_or(0, current);
            if have & 3 != 3 {
                w.modify(catalog)?
                    .as_dict_mut()
                    .ok()
                    .and_then(|c| c.get_mut(b"AcroForm").ok())
                    .and_then(|f| f.as_dict_mut().ok())
                    .ok_or_else(|| bad("AcroForm is not a dictionary"))?
                    .set("SigFlags", have | 3);
            }
            Ok(())
        }
    }
}

/// The page rectangle used for placement: the crop box, with width and height swapped
/// for pages rotated by 90 or 270 degrees.
fn sized_box(page: &Page) -> [f32; 4] {
    let [llx, lly, urx, ury] = page.crop_box;
    if page.rotation.is_multiple_of(180) {
        [llx, lly, urx, ury]
    } else {
        [lly, llx, ury, urx]
    }
}

/// Checks `rect` against the page and clips what overhangs the top and right edges.
fn place_rect(rect: [f32; 4], page: [f32; 4]) -> Result<[f32; 4]> {
    let invalid = || Error::Pdf(ErrorCode::INVALID_SIGNATURE_POSITION);
    let [llx, lly, urx, ury] = [
        rect[0].min(rect[2]),
        rect[1].min(rect[3]),
        rect[0].max(rect[2]),
        rect[1].max(rect[3]),
    ];
    if rect.iter().any(|n| !n.is_finite()) || urx <= llx || ury <= lly {
        return Err(invalid());
    }
    let [pl, pb, pr, pt] = page;
    if llx >= pr || lly >= pt || urx <= pl || ury <= pb {
        return Err(invalid());
    }
    Ok([llx, lly, urx.min(pr), ury.min(pt)])
}

/// Adds a blank page, as large as page one, at the end of the page tree.
fn append_page(w: &mut IncrementalWriter<'_>, first: &Page) -> Result<ObjectId> {
    let root = w
        .get(catalog_id(w)?)
        .and_then(|o| o.as_dict().ok())
        .and_then(|c| c.get(b"Pages").ok())
        .and_then(|o| o.as_reference().ok())
        .ok_or_else(|| bad("catalog has no /Pages reference"))?;
    let [llx, lly, urx, ury] = sized_box(first);
    let (width, height) = (urx - llx, ury - lly);

    let mut page = Dictionary::new();
    page.set("Type", Object::Name(b"Page".to_vec()));
    page.set("Parent", root);
    page.set(
        "MediaBox",
        vec![
            Object::Integer(0),
            Object::Integer(0),
            Object::Real(width),
            Object::Real(height),
        ],
    );
    page.set("Resources", Object::Dictionary(Dictionary::new()));
    let page_id = w.add_object(Object::Dictionary(page));

    push_to_array(w, root, b"Kids", page_id)?;
    let node = w
        .modify(root)?
        .as_dict_mut()
        .map_err(|_| bad("page tree root is not a dictionary"))?;
    let count = node
        .get(b"Count")
        .ok()
        .and_then(|o| o.as_i64().ok())
        .unwrap_or(0);
    node.set("Count", count + 1);
    Ok(page_id)
}
