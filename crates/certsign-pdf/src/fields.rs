use crate::pages::{Page, name_of, normalize, rect};
use lopdf::{Dictionary, Document, Object, ObjectId, decode_text_string};
use std::collections::HashSet;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcroForm {
    pub id: Option<ObjectId>,
    pub sig_flags: i64,
    pub need_appearances: bool,
}

/// The signature dictionary referenced by a field's `/V`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureValue {
    pub id: Option<ObjectId>,
    pub filter: Option<String>,
    pub sub_filter: Option<String>,
    pub byte_range: Option<Vec<i64>>,
    /// `/Type /DocTimeStamp` or `/SubFilter /ETSI.RFC3161`. Not a signature.
    pub is_doc_timestamp: bool,
    /// DocMDP `/P` when this is a certification signature.
    pub docmdp: Option<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignatureField {
    /// Fully qualified field name, parts joined by `.`.
    pub name: String,
    pub id: ObjectId,
    pub widget_id: ObjectId,
    /// 1-based page holding the widget, when it can be found.
    pub page: Option<u32>,
    pub rect: Option<[f32; 4]>,
    pub value: Option<SignatureValue>,
}

impl SignatureField {
    pub fn is_signed(&self) -> bool {
        self.value.is_some()
    }

    /// Signed with a real signature, as opposed to a document timestamp.
    pub fn is_signature(&self) -> bool {
        self.value.as_ref().is_some_and(|v| !v.is_doc_timestamp)
    }

    pub fn is_doc_timestamp(&self) -> bool {
        self.value.as_ref().is_some_and(|v| v.is_doc_timestamp)
    }
}

const MAX_DEPTH: usize = 32;

pub(crate) fn acroform(doc: &Document) -> Option<(AcroForm, Dictionary)> {
    let catalog = doc.catalog().ok()?;
    let entry = catalog.get(b"AcroForm").ok()?;
    let id = entry.as_reference().ok();
    let (_, obj) = doc.dereference(entry).ok()?;
    let dict = obj.as_dict().ok()?;
    let form = AcroForm {
        id,
        sig_flags: dict
            .get(b"SigFlags")
            .ok()
            .and_then(|o| o.as_i64().ok())
            .unwrap_or(0),
        need_appearances: dict
            .get(b"NeedAppearances")
            .ok()
            .and_then(|o| o.as_bool().ok())
            .unwrap_or(false),
    };

    Some((form, dict.clone()))
}

pub(crate) fn signature_fields(doc: &Document, pages: &[Page]) -> Vec<SignatureField> {
    let Some((_, form)) = acroform(doc) else {
        return Vec::new();
    };

    let Some(roots) = form
        .get(b"Fields")
        .ok()
        .and_then(|o| doc.dereference(o).ok())
        .and_then(|(_, o)| o.as_array().ok())
    else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for root in roots {
        if let Ok(id) = root.as_reference() {
            visit(doc, pages, id, "", None, None, 0, &mut seen, &mut out);
        }
    }

    out
}

fn text(doc: &Document, obj: &Object) -> Option<String> {
    let (_, obj) = doc.dereference(obj).ok()?;
    decode_text_string(obj).ok().or_else(|| {
        obj.as_str()
            .ok()
            .map(|b| String::from_utf8_lossy(b).into_owned())
    })
}

#[allow(clippy::too_many_arguments)]
fn visit(
    doc: &Document,
    pages: &[Page],
    id: ObjectId,
    parent_name: &str,
    inherited_ft: Option<String>,
    inherited_v: Option<Object>,
    depth: usize,
    seen: &mut HashSet<ObjectId>,
    out: &mut Vec<SignatureField>,
) {
    if depth > MAX_DEPTH || !seen.insert(id) {
        return;
    }

    let Ok(dict) = doc.get_dictionary(id) else {
        return;
    };

    let partial = dict.get(b"T").ok().and_then(|o| text(doc, o));

    let name = match (&partial, parent_name.is_empty()) {
        (Some(t), true) => t.clone(),
        (Some(t), false) => format!("{parent_name}.{t}"),
        (None, _) => parent_name.to_owned(),
    };

    let ft = name_of(dict, b"FT").or(inherited_ft);
    let v = dict.get(b"V").ok().cloned().or(inherited_v);
    let kids: Vec<ObjectId> = dict
        .get(b"Kids")
        .ok()
        .and_then(|o| doc.dereference(o).ok())
        .and_then(|(_, o)| o.as_array().ok())
        .map(|a| a.iter().filter_map(|k| k.as_reference().ok()).collect())
        .unwrap_or_default();

    // Kids with a partial name (or their own kids) are subfields; the rest are widgets of this field.
    let is_field = |k: &ObjectId| {
        doc.get_dictionary(*k)
            .map(|d| d.has(b"T") || d.has(b"Kids"))
            .unwrap_or(false)
    };
    let (subfields, widgets): (Vec<ObjectId>, Vec<ObjectId>) =
        kids.iter().copied().partition(is_field);

    for k in subfields {
        visit(
            doc,
            pages,
            k,
            &name,
            ft.clone(),
            v.clone(),
            depth + 1,
            seen,
            out,
        );
    }

    if ft.as_deref() == Some("Sig") && (kids.is_empty() || !widgets.is_empty()) {
        let widget_id = widgets.first().copied().unwrap_or(id);
        let widget = doc.get_dictionary(widget_id).unwrap_or(dict);
        let value = v.as_ref().and_then(|v| signature_value(doc, v));

        out.push(SignatureField {
            name,
            id,
            widget_id,
            page: page_of(doc, pages, widget_id, widget),
            rect: widget
                .get(b"Rect")
                .ok()
                .and_then(|o| rect(doc, o))
                .map(normalize),
            value,
        });
    }
}

fn page_of(
    doc: &Document,
    pages: &[Page],
    widget_id: ObjectId,
    widget: &Dictionary,
) -> Option<u32> {
    if let Some(p) = widget.get(b"P").ok().and_then(|o| o.as_reference().ok())
        && let Some(page) = pages.iter().find(|pg| pg.id == p)
    {
        return Some(page.number);
    }

    pages.iter().find_map(|page| {
        let annots = doc
            .get_dictionary(page.id)
            .ok()?
            .get(b"Annots")
            .ok()
            .and_then(|o| doc.dereference(o).ok())?
            .1
            .as_array()
            .ok()?;
        annots
            .iter()
            .any(|a| a.as_reference().ok() == Some(widget_id))
            .then_some(page.number)
    })
}

pub(crate) fn signature_value(doc: &Document, v: &Object) -> Option<SignatureValue> {
    let (id, obj) = doc.dereference(v).ok()?;
    let dict = obj.as_dict().ok()?;

    // An empty or placeholder `/V` that is not a dictionary means unsigned.
    if dict.is_empty() {
        return None;
    }

    let sub_filter = name_of(dict, b"SubFilter");
    let is_doc_timestamp = name_of(dict, b"Type").as_deref() == Some("DocTimeStamp")
        || sub_filter.as_deref() == Some("ETSI.RFC3161");

    Some(SignatureValue {
        id,
        filter: name_of(dict, b"Filter"),
        sub_filter,
        byte_range: dict
            .get(b"ByteRange")
            .ok()
            .and_then(|o| doc.dereference(o).ok())
            .and_then(|(_, o)| o.as_array().ok())
            .map(|a| a.iter().filter_map(|n| n.as_i64().ok()).collect()),
        is_doc_timestamp,
        docmdp: docmdp(doc, dict),
    })
}

/// `/Reference` transform of type DocMDP: returns its `/P` (default 2).
fn docmdp(doc: &Document, sig: &Dictionary) -> Option<u8> {
    let refs = sig
        .get(b"Reference")
        .ok()
        .and_then(|o| doc.dereference(o).ok())?
        .1
        .as_array()
        .ok()?;

    refs.iter().find_map(|r| {
        let rd = doc.dereference(r).ok()?.1.as_dict().ok()?;

        if name_of(rd, b"TransformMethod").as_deref() != Some("DocMDP") {
            return None;
        }

        let params = rd
            .get(b"TransformParams")
            .ok()
            .and_then(|o| doc.dereference(o).ok())?
            .1
            .as_dict()
            .ok()?;
        Some(
            params
                .get(b"P")
                .ok()
                .and_then(|p| p.as_i64().ok())
                .unwrap_or(2)
                .clamp(0, 255) as u8,
        )
    })
}

/// Certification level from the catalog's `/Perms /DocMDP` entry.
pub(crate) fn certification_level(doc: &Document) -> Option<u8> {
    let catalog = doc.catalog().ok()?;
    let perms = catalog
        .get(b"Perms")
        .ok()
        .and_then(|o| doc.dereference(o).ok())?
        .1
        .as_dict()
        .ok()?;
    let sig = perms.get(b"DocMDP").ok()?;

    signature_value(doc, sig)?.docmdp
}

/// Fully qualified names of every terminal and non-terminal field in the form.
pub(crate) fn all_field_names(doc: &Document) -> HashSet<String> {
    fn walk(doc: &Document, id: ObjectId, parent: &str, depth: usize, out: &mut HashSet<String>) {
        if depth > MAX_DEPTH {
            return;
        }
        let Ok(dict) = doc.get_dictionary(id) else {
            return;
        };
        let name = match dict.get(b"T").ok().and_then(|o| text(doc, o)) {
            Some(t) if parent.is_empty() => t,
            Some(t) => format!("{parent}.{t}"),
            None => parent.to_owned(),
        };
        if !name.is_empty() && !out.insert(name.clone()) {
            // Already seen: a cycle or a repeated reference.
            return;
        }
        if let Some(kids) = dict
            .get(b"Kids")
            .ok()
            .and_then(|o| doc.dereference(o).ok())
            .and_then(|(_, o)| o.as_array().ok())
        {
            for kid in kids.iter().filter_map(|k| k.as_reference().ok()) {
                walk(doc, kid, &name, depth + 1, out);
            }
        }
    }
    let mut out = HashSet::new();
    if let Some((_, form)) = acroform(doc)
        && let Some(roots) = form
            .get(b"Fields")
            .ok()
            .and_then(|o| doc.dereference(o).ok())
            .and_then(|(_, o)| o.as_array().ok())
    {
        for root in roots.iter().filter_map(|r| r.as_reference().ok()) {
            walk(doc, root, "", 0, &mut out);
        }
    }
    out
}
