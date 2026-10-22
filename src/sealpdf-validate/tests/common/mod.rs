#![allow(dead_code)]
// Fixtures: the PKI and PDFs of the signing tests, signed documents, and ways to damage them.

#[path = "../../../sealpdf-pades/tests/common/mod.rs"]
mod pades;

pub use pades::{Leaf, Pki, blank_pdf};

use chrono::{DateTime, TimeZone, Utc};
use cms::signed_data::SignedData;
use der::{Any, Decode, Encode};
use lopdf::{Dictionary, IncrementalDocument, Object, dictionary};
use sealpdf_cms::{PadesCms, PadesCmsOptions};
use sealpdf_core::{DigestAlg, FixedClock, KeyType, SigAlg};
use sealpdf_keystore::{KeyStore, NoPrompt, Pkcs12KeyStore, StaticPrompt};
use sealpdf_pades::{SigningParams, sign_pdf};
use sealpdf_pdf::{FieldTarget, IncrementalWriter, PdfDocument, attach_signature};

pub const SIGNING_TIME: fn() -> DateTime<Utc> =
    || Utc.with_ymd_and_hms(2024, 5, 17, 10, 30, 0).unwrap();

/// The time certificates are compared with: the present, when the test certificates are valid.
pub fn now() -> FixedClock {
    FixedClock(Utc::now())
}

pub fn at(year: i32) -> FixedClock {
    FixedClock(Utc.with_ymd_and_hms(year, 1, 1, 0, 0, 0).unwrap())
}

/// A key store over a PKCS#12 file that holds `leaf`.
pub fn store(pki: &Pki, leaf: &Leaf) -> Pkcs12KeyStore {
    let path = pki.p12(leaf, "pw", &[]);
    Pkcs12KeyStore::open(path, &StaticPrompt::new("pw")).unwrap()
}

pub fn sign(pdf: &[u8], store: &dyn KeyStore, alias: &str) -> Vec<u8> {
    sign_pdf(
        pdf.to_vec(),
        store,
        alias,
        &FixedClock(SIGNING_TIME()),
        &NoPrompt,
        &SigningParams::default(),
    )
    .unwrap()
}

/// Signs like `sign_pdf`, without its refusals, and lets `dict` add entries to the signature
/// dictionary and `catalog` to the document, to make certified documents.
pub fn sign_unchecked(
    input: &[u8],
    store: &dyn KeyStore,
    alias: &str,
    certify: Option<i64>,
) -> Vec<u8> {
    let pdf = PdfDocument::open(input.to_vec(), None).unwrap();
    let entry = store
        .entries()
        .unwrap()
        .into_iter()
        .find(|e| e.alias == alias)
        .unwrap();
    let alg = SigAlg::new(DigestAlg::Sha256, KeyType::Rsa);
    let cms = PadesCms::new(alg, entry.chain(), PadesCmsOptions::default()).unwrap();

    let mut dict = dictionary! {
        "Type" => "Sig",
        "Filter" => "Adobe.PPKLite",
        "SubFilter" => "adbe.pkcs7.detached",
    };
    let mut writer = IncrementalWriter::new(&pdf).unwrap();
    if let Some(p) = certify {
        let params =
            writer.add_object(dictionary! { "Type" => "TransformParams", "P" => p, "V" => "1.2" });
        dict.set(
            "Reference",
            vec![Object::Dictionary(dictionary! {
                "Type" => "SigRef",
                "TransformMethod" => "DocMDP",
                "TransformParams" => params,
            })],
        );
    }
    let sig = writer.add_signature(dict, 27_000).unwrap();
    if certify.is_some() {
        let catalog = pdf
            .document()
            .trailer
            .get(b"Root")
            .unwrap()
            .as_reference()
            .unwrap();
        let perms = writer.add_object(dictionary! { "DocMDP" => sig });
        writer
            .modify(catalog)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("Perms", perms);
    }
    attach_signature(
        &mut writer,
        &FieldTarget::New {
            page: sealpdf_core::Page::Number(1),
            rect: None,
        },
        sig,
    )
    .unwrap();
    let prepared = writer.finish_signature().unwrap();
    let covered = prepared.signed_parts().concat();
    let attributes = cms.signed_attributes(&cms.digest(&covered)).unwrap();
    let value = store
        .sign(alias, alg, &attributes.to_sign().unwrap(), &NoPrompt)
        .unwrap();
    prepared
        .embed(&cms.assemble(&attributes, &value).unwrap())
        .unwrap()
}

/// Where the hex digits of the `n`th signature's `/Contents` are: `(first digit, one past last)`.
pub fn contents_span(file: &[u8], n: usize) -> (usize, usize) {
    let pdf = PdfDocument::open(file.to_vec(), None).unwrap();
    let range = pdf
        .signature_fields()
        .into_iter()
        .filter(|f| f.is_signed())
        .nth(n)
        .unwrap()
        .value
        .unwrap()
        .byte_range
        .unwrap();
    (range[1] as usize + 1, range[2] as usize - 1)
}

fn from_hex(hex: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(hex).unwrap();
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// The length of the DER element at the start of `data`, header included.
fn der_len(data: &[u8]) -> usize {
    if data[1] < 0x80 {
        2 + data[1] as usize
    } else {
        let n = (data[1] & 0x7F) as usize;
        2 + n
            + data[2..2 + n]
                .iter()
                .fold(0usize, |a, b| (a << 8) | *b as usize)
    }
}

/// Replaces the `/Contents` of the `n`th signature with `cms`, zero padded to the same width.
pub fn put_contents(file: &[u8], n: usize, cms: &[u8]) -> Vec<u8> {
    let (from, to) = contents_span(file, n);
    let mut hex: String = cms.iter().map(|b| format!("{b:02X}")).collect();
    assert!(hex.len() <= to - from, "the new CMS must fit");
    hex.extend(std::iter::repeat_n('0', to - from - hex.len()));
    let mut out = file.to_vec();
    out[from..to].copy_from_slice(hex.as_bytes());
    out
}

/// Decodes the CMS of the `n`th signature, lets `edit` change it and writes it back.
pub fn edit_cms(file: &[u8], n: usize, edit: impl FnOnce(&mut SignedData)) -> Vec<u8> {
    let (from, to) = contents_span(file, n);
    let raw = from_hex(&file[from..to]);
    let der = &raw[..der_len(&raw)];
    let mut info = cms::content_info::ContentInfo::from_der(der).unwrap();
    let mut signed: SignedData = info.content.decode_as().unwrap();
    edit(&mut signed);
    info.content = Any::encode_from(&signed).unwrap();
    put_contents(file, n, &info.to_der().unwrap())
}

/// Appends an incremental update produced by `edit`.
pub fn append_revision(bytes: &[u8], edit: impl FnOnce(&mut IncrementalDocument)) -> Vec<u8> {
    let prev = lopdf::Document::load_mem(bytes).unwrap();
    let mut inc = IncrementalDocument::create_from(bytes.to_vec(), prev);
    edit(&mut inc);
    let mut out = Vec::new();
    inc.save_to(&mut out).unwrap();
    out
}

/// An update that changes nothing the signatures could notice: a new, unused object.
pub fn touch(bytes: &[u8]) -> Vec<u8> {
    append_revision(bytes, |inc| {
        let catalog = inc
            .get_prev_documents()
            .trailer
            .get(b"Root")
            .unwrap()
            .as_reference()
            .unwrap();
        inc.opt_clone_object_to_new_document(catalog).unwrap();
        inc.new_document
            .get_object_mut(catalog)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("Lang", Object::string_literal("en"));
    })
}

pub fn dictionary_with(entries: &[(&str, Object)]) -> Dictionary {
    let mut d = Dictionary::new();
    for (k, v) in entries {
        d.set(*k, v.clone());
    }
    d
}

pub fn open(bytes: Vec<u8>) -> PdfDocument {
    PdfDocument::open(bytes, None).unwrap()
}

/// The CMS inside the `n`th signature's `/Contents`, without the padding.
pub fn cms_of(file: &[u8], n: usize) -> Vec<u8> {
    let (from, to) = contents_span(file, n);
    let raw = from_hex(&file[from..to]);
    raw[..der_len(&raw)].to_vec()
}

/// Appends a document timestamp whose token is `token`. Only the digest algorithm of a token
/// is looked at, so a CMS made by a test signature stands in for a real one.
pub fn with_doc_timestamp(file: &[u8], token: &[u8]) -> Vec<u8> {
    let pdf = open(file.to_vec());
    let mut writer = IncrementalWriter::new(&pdf).unwrap();
    let id = writer
        .add_signature(
            dictionary! {
                "Type" => "DocTimeStamp",
                "Filter" => "Adobe.PPKLite",
                "SubFilter" => "ETSI.RFC3161",
            },
            27_000,
        )
        .unwrap();
    attach_signature(
        &mut writer,
        &FieldTarget::New {
            page: sealpdf_core::Page::Number(1),
            rect: None,
        },
        id,
    )
    .unwrap();
    writer.finish_signature().unwrap().embed(token).unwrap()
}

/// Adds a `/DSS` dictionary to the catalog in a new revision.
pub fn with_dss(file: &[u8]) -> Vec<u8> {
    let pdf = open(file.to_vec());
    let mut writer = IncrementalWriter::new(&pdf).unwrap();
    let catalog = pdf
        .document()
        .trailer
        .get(b"Root")
        .unwrap()
        .as_reference()
        .unwrap();
    let dss = writer.add_object(dictionary! { "Certs" => Vec::<Object>::new() });
    writer
        .modify(catalog)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("DSS", dss);
    writer.finish().unwrap()
}

/// A PDF with one signature field that nobody signed.
pub fn unsigned_field_pdf() -> Vec<u8> {
    let mut doc = lopdf::Document::load_mem(&blank_pdf(1, false)).unwrap();
    let page = *doc.get_pages().get(&1).unwrap();
    let widget = doc.add_object(dictionary! {
        "Type" => "Annot", "Subtype" => "Widget", "FT" => "Sig",
        "T" => Object::string_literal("Empty"), "F" => 132, "P" => page,
        "Rect" => vec![0.into(), 0.into(), 0.into(), 0.into()],
    });
    doc.get_object_mut(page)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Annots", vec![Object::Reference(widget)]);
    let form = doc.add_object(dictionary! {
        "Fields" => vec![Object::Reference(widget)], "SigFlags" => 3,
    });
    let catalog = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    doc.get_object_mut(catalog)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("AcroForm", form);
    doc.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}

/// A PDF with only a document timestamp.
pub fn timestamp_only_pdf(token: &[u8]) -> Vec<u8> {
    with_doc_timestamp(&blank_pdf(1, false), token)
}
