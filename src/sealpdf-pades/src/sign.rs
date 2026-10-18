use chrono::{DateTime, Datelike, Timelike, Utc};
use der::Decode;
use lopdf::{Dictionary, Object, StringFormat};
use sealpdf_cms::{PadesCms, PadesCmsOptions};
use sealpdf_core::{Clock, Error, ErrorCode, KeystoreError, Page, Result, SigAlg};
use sealpdf_core::{DigestAlg, KeyType};
use sealpdf_keystore::{AuthPrompt, KeyStore};
use sealpdf_pdf::{FieldTarget, IncrementalWriter, PdfDocument, attach_signature};
use x509_cert::Certificate;

/// Knobs of a signature. The defaults are what an ordinary signature uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningParams {
    /// Bytes reserved for the CMS in `/Contents`. Signing fails, writing nothing, if it does not fit.
    pub reserved_size: usize,
}

impl Default for SigningParams {
    fn default() -> Self {
        Self {
            reserved_size: 27_000,
        }
    }
}

const CN: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("2.5.4.3");
const RSA: &str = "1.2.840.113549.1.1.1";
const EC: &str = "1.2.840.10045.2.1";
const P256: &str = "1.2.840.10045.3.1.7";
const P384: &str = "1.3.132.0.34";

/// The algorithm for a key: SHA-256 for RSA and P-256, SHA-384 for P-384.
fn algorithm_for(cert: &Certificate) -> Result<SigAlg> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    match spki.algorithm.oid.to_string().as_str() {
        RSA => Ok(SigAlg::new(DigestAlg::Sha256, KeyType::Rsa)),
        EC => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
                .map(|o| o.to_string());
            match curve.as_deref() {
                Some(P256) => Ok(SigAlg::new(DigestAlg::Sha256, KeyType::Ecdsa)),
                Some(P384) => Ok(SigAlg::new(DigestAlg::Sha384, KeyType::Ecdsa)),
                other => Err(Error::UnsupportedAlgorithm(format!(
                    "elliptic curve {}",
                    other.unwrap_or("(unnamed)")
                ))),
            }
        }
        other => Err(Error::UnsupportedAlgorithm(format!(
            "public key algorithm {other}"
        ))),
    }
}

/// The text of a directory string, by its ASN.1 string type.
fn directory_string(value: &der::Any) -> Option<String> {
    use der::{Tag, Tagged};
    let bytes = value.value();
    match value.tag() {
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String => {
            std::str::from_utf8(bytes).ok().map(str::to_owned)
        }
        // TeletexString is treated as Latin-1, which is how it is used in practice.
        Tag::TeletexString => Some(bytes.iter().map(|b| char::from(*b)).collect()),
        Tag::BmpString => {
            let units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes(*c))
                .collect();
            String::from_utf16(&units).ok()
        }
        _ => None,
    }
}

/// The subject's common name, for the signature's `/Name`.
fn common_name(cert: &Certificate) -> Option<String> {
    cert.tbs_certificate()
        .subject()
        .iter()
        .find(|a| a.oid == CN)
        .and_then(|a| directory_string(&a.value))
}

/// A PDF text string: plain bytes for ASCII, UTF-16BE with a byte order mark otherwise.
fn text_string(text: &str) -> Object {
    if text.is_ascii() {
        return Object::String(text.as_bytes().to_vec(), StringFormat::Literal);
    }
    let mut bytes = vec![0xFE, 0xFF];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_be_bytes());
    }
    Object::String(bytes, StringFormat::Literal)
}

/// A PDF date: `D:YYYYMMDDHHmmSS+00'00'`, in UTC.
fn pdf_date(time: DateTime<Utc>) -> Object {
    let text = format!(
        "D:{:04}{:02}{:02}{:02}{:02}{:02}+00'00'",
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    );
    Object::String(text.into_bytes(), StringFormat::Literal)
}

/// Signs `input` with the identity `alias` of `keystore`, invisibly, and returns the new file.
///
/// The result is `input` followed by one incremental update, so earlier signatures stay valid.
/// The signature carries no appearance and the pages are untouched. The document is refused,
/// with nothing written, when it is encrypted, certified with no changes allowed, has no pages
/// or cannot be read.
pub fn sign_pdf(
    input: Vec<u8>,
    keystore: &dyn KeyStore,
    alias: &str,
    clock: &dyn Clock,
    auth: &dyn AuthPrompt,
    params: &SigningParams,
) -> Result<Vec<u8>> {
    let pdf = PdfDocument::open(input, None)?;
    if pdf.is_encrypted() {
        return Err(Error::Refused(
            "the PDF is encrypted; signing encrypted PDFs is not supported yet".into(),
        ));
    }
    if pdf.certification_level() == Some(1) {
        return Err(ErrorCode::PDF_CERTIFIED.into());
    }
    if pdf.pages().is_empty() {
        return Err(Error::InvalidPdf("the document has no pages".into()));
    }

    let entry = keystore
        .entries()?
        .into_iter()
        .find(|e| e.alias == alias)
        .ok_or_else(|| Error::from(KeystoreError::UnknownAlias(alias.to_owned())))?;
    let cert = Certificate::from_der(entry.certificate())
        .map_err(|e| Error::Other(format!("unreadable signing certificate: {e}")))?;
    let alg = algorithm_for(&cert)?;
    let cms = PadesCms::new(alg, entry.chain(), PadesCmsOptions::default())?;

    let mut dict = Dictionary::new();
    dict.set("Type", Object::Name(b"Sig".to_vec()));
    dict.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    dict.set("SubFilter", Object::Name(b"adbe.pkcs7.detached".to_vec()));
    if let Some(name) = common_name(&cert) {
        dict.set("Name", text_string(&name));
    }
    dict.set("M", pdf_date(clock.now()));

    let mut writer = IncrementalWriter::new(&pdf)?;
    let signature = writer.add_signature(dict, params.reserved_size)?;
    attach_signature(
        &mut writer,
        &FieldTarget::New {
            page: Page::Number(1),
            rect: None,
        },
        signature,
    )?;
    let prepared = writer.finish_signature()?;

    let covered = prepared.signed_parts().concat();
    let attributes = cms.signed_attributes(&cms.digest(&covered))?;
    let value = keystore.sign(alias, alg, &attributes.to_sign()?, auth)?;
    let der = cms.assemble(&attributes, &value)?;
    prepared.embed(&der)
}
