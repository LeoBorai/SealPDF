#![allow(dead_code)]

use lopdf::{Document, IncrementalDocument, Object, ObjectId, StringFormat, dictionary};

pub fn int(n: i64) -> Object {
    Object::Integer(n)
}

pub fn name(s: &str) -> Object {
    Object::Name(s.as_bytes().to_vec())
}

pub fn text(s: &str) -> Object {
    Object::String(s.as_bytes().to_vec(), StringFormat::Literal)
}

/// A document with `pages` empty pages. The MediaBox is inherited from the page tree root.
pub fn base(pages: usize) -> (Document, Vec<ObjectId>) {
    let mut doc = Document::with_version("1.5");
    let pages_id = doc.new_object_id();
    let page_ids: Vec<ObjectId> = (0..pages)
        .map(|_| {
            doc.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
            })
        })
        .collect();
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => page_ids.iter().map(|id| Object::Reference(*id)).collect::<Vec<_>>(),
            "Count" => pages as i64,
            "MediaBox" => vec![int(0), int(0), int(595), int(842)],
        }),
    );
    let catalog = doc.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    doc.trailer.set("Root", catalog);
    let id = Object::String(b"sealpdf-test-id!".to_vec(), StringFormat::Hexadecimal);
    doc.trailer.set("ID", vec![id.clone(), id]);
    (doc, page_ids)
}

/// Saves with a classic `xref` table.
pub fn save(doc: &mut Document) -> Vec<u8> {
    doc.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}

/// Saves with xref streams and object streams.
pub fn save_modern(doc: &mut Document) -> Vec<u8> {
    let mut out = Vec::new();
    doc.save_modern(&mut out).unwrap();
    out
}

pub fn catalog_id(doc: &Document) -> ObjectId {
    doc.trailer.get(b"Root").unwrap().as_reference().unwrap()
}

/// Adds a signature field with its widget on `page`, creating the AcroForm if needed.
/// `value` is the field's `/V` (a signature dictionary id) when signed.
pub fn add_sig_field(
    doc: &mut Document,
    page: ObjectId,
    field_name: &str,
    rect: [i64; 4],
    value: Option<ObjectId>,
) -> ObjectId {
    let mut widget = dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "FT" => "Sig",
        "T" => text(field_name),
        "F" => 132,
        "Rect" => rect.iter().map(|n| int(*n)).collect::<Vec<_>>(),
        "P" => page,
    };
    if let Some(v) = value {
        widget.set("V", v);
    }
    let widget_id = doc.add_object(widget);
    attach_to_page(doc, page, widget_id);
    attach_to_form(doc, widget_id);
    widget_id
}

fn attach_to_page(doc: &mut Document, page: ObjectId, widget: ObjectId) {
    let dict = doc.get_object_mut(page).unwrap().as_dict_mut().unwrap();
    if let Ok(Object::Array(a)) = dict.get_mut(b"Annots") {
        a.push(widget.into());
    } else {
        dict.set("Annots", vec![Object::Reference(widget)]);
    }
}

fn attach_to_form(doc: &mut Document, widget: ObjectId) {
    let catalog = catalog_id(doc);
    let existing = doc
        .get_dictionary(catalog)
        .unwrap()
        .get(b"AcroForm")
        .ok()
        .and_then(|o| o.as_reference().ok());
    match existing {
        Some(form) => {
            let dict = doc.get_object_mut(form).unwrap().as_dict_mut().unwrap();
            dict.get_mut(b"Fields")
                .unwrap()
                .as_array_mut()
                .unwrap()
                .push(widget.into());
        }
        None => {
            let form = doc.add_object(dictionary! {
                "Fields" => vec![Object::Reference(widget)],
                "SigFlags" => 3,
            });
            doc.get_object_mut(catalog)
                .unwrap()
                .as_dict_mut()
                .unwrap()
                .set("AcroForm", form);
        }
    }
}

pub struct SigSpec {
    pub sub_filter: &'static str,
    pub doc_timestamp: bool,
    pub docmdp: Option<i64>,
}

impl Default for SigSpec {
    fn default() -> Self {
        Self {
            sub_filter: "adbe.pkcs7.detached",
            doc_timestamp: false,
            docmdp: None,
        }
    }
}

/// A signature dictionary with a placeholder `/ByteRange` and `/Contents`.
pub fn sig_dict(doc: &mut Document, spec: &SigSpec) -> ObjectId {
    let mut d = dictionary! {
        "Type" => if spec.doc_timestamp { "DocTimeStamp" } else { "Sig" },
        "Filter" => "Adobe.PPKLite",
        "SubFilter" => spec.sub_filter,
        "ByteRange" => vec![int(0), int(10), int(20), int(30)],
        "Contents" => Object::String(vec![0; 16], StringFormat::Hexadecimal),
    };
    if let Some(p) = spec.docmdp {
        let params =
            doc.add_object(dictionary! { "Type" => "TransformParams", "P" => p, "V" => "1.2" });
        d.set(
            "Reference",
            vec![Object::Dictionary(dictionary! {
                "Type" => "SigRef",
                "TransformMethod" => "DocMDP",
                "TransformParams" => params,
            })],
        );
    }
    doc.add_object(d)
}

/// Appends an incremental update produced by `edit` to `bytes`.
pub fn append_revision(bytes: &[u8], edit: impl FnOnce(&mut IncrementalDocument)) -> Vec<u8> {
    let prev = Document::load_mem(bytes).unwrap();
    let mut inc = IncrementalDocument::create_from(bytes.to_vec(), prev);
    edit(&mut inc);
    let mut out = Vec::new();
    inc.save_to(&mut out).unwrap();
    out
}
