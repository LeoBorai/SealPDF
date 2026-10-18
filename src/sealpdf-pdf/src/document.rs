use crate::{
    fields::{self, AcroForm, SignatureField},
    pages::{self, Page},
    revisions::{self, Revision},
};
use lopdf::{Document, LoadOptions};
use sealpdf_core::{Error, ErrorCode, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionInfo {
    /// `/V` of the standard security handler.
    pub version: i64,
    /// `/R` of the standard security handler.
    pub revision: i64,
    /// Key length in bits, when the file states one.
    pub key_length: Option<usize>,
}

/// A parsed PDF, decrypted in memory when a password opened it.
pub struct PdfDocument {
    bytes: Vec<u8>,
    doc: Document,
    encryption: Option<EncryptionInfo>,
    revisions: Vec<Revision>,
    pages: Vec<Page>,
}

fn map_lopdf(e: lopdf::Error) -> Error {
    let msg = e.to_string();
    match e {
        lopdf::Error::InvalidPassword => ErrorCode::PDF_BAD_PASSWORD.into(),
        _ if msg.contains("password is incorrect") => ErrorCode::PDF_BAD_PASSWORD.into(),
        _ => Error::InvalidPdf(msg),
    }
}

impl PdfDocument {
    /// Parses `bytes`. `password` may be the user or the owner password.
    ///
    /// Fails with `PDF_PASSWORD_REQUIRED` when the file needs a password and none was given,
    /// and with `PDF_BAD_PASSWORD` when the given one is wrong.
    pub fn open(bytes: Vec<u8>, password: Option<&str>) -> Result<Self> {
        let head = &bytes[..bytes.len().min(1024)];

        if !head.windows(5).any(|w| w == b"%PDF-") {
            return Err(Error::InvalidPdf("missing %PDF- header".into()));
        }

        let options = match password {
            Some(p) => LoadOptions::with_password(p),
            None => LoadOptions::default(),
        };
        let doc = Document::load_mem_with_options(&bytes, options).map_err(map_lopdf)?;

        if doc.trailer.get(b"Encrypt").is_ok() {
            return Err(ErrorCode::PDF_PASSWORD_REQUIRED.into());
        }

        let encryption = doc.encryption_state.as_ref().map(|s| EncryptionInfo {
            version: s.version(),
            revision: s.revision(),
            key_length: s.key_length(),
        });
        let revisions = revisions::scan(&bytes);
        let pages = pages::read_pages(&doc);

        Ok(Self {
            bytes,
            doc,
            encryption,
            revisions,
            pages,
        })
    }

    /// The original, unmodified bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn document(&self) -> &Document {
        &self.doc
    }

    /// `Some` when the file is encrypted (and was opened).
    pub fn encryption(&self) -> Option<EncryptionInfo> {
        self.encryption
    }

    pub fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    pub fn revisions(&self) -> &[Revision] {
        &self.revisions
    }

    pub fn pages(&self) -> &[Page] {
        &self.pages
    }

    pub fn page(&self, number: u32) -> Option<&Page> {
        self.pages.iter().find(|p| p.number == number)
    }

    pub fn acroform(&self) -> Option<AcroForm> {
        fields::acroform(&self.doc).map(|(f, _)| f)
    }

    /// Every signature field in the form, signed or not, including document timestamps.
    pub fn signature_fields(&self) -> Vec<SignatureField> {
        fields::signature_fields(&self.doc, &self.pages)
    }

    /// Signed fields that hold real signatures, not document timestamps.
    pub fn signatures(&self) -> Vec<SignatureField> {
        let mut f = self.signature_fields();
        f.retain(SignatureField::is_signature);
        f
    }

    pub fn document_timestamps(&self) -> Vec<SignatureField> {
        let mut f = self.signature_fields();
        f.retain(SignatureField::is_doc_timestamp);
        f
    }

    /// DocMDP level (1 to 3) when the document is certified.
    pub fn certification_level(&self) -> Option<u8> {
        fields::certification_level(&self.doc)
    }
}
