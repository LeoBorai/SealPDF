use sealpdf_core::{ValidityError, Verdict};
use serde::Serialize;

/// The version of the JSON form of [`Report`]. Raised when a field changes meaning or goes away.
pub const REPORT_VERSION: u32 = 1;

/// What `inspect` found in a PDF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub version: u32,
    /// Number of revisions of the file.
    pub revisions: usize,
    /// Every signed signature field, oldest first. Document timestamps are included.
    pub signatures: Vec<SignatureInfo>,
    /// The document verdict list. Never empty.
    pub verdicts: Vec<Verdict>,
    /// Always `false`: certificate chains and revocation are not checked.
    pub trust_checked: bool,
}

/// One signed signature field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureInfo {
    /// Fully qualified field name.
    pub field: String,
    /// 1-based page of the field's widget, when it can be found.
    pub page: Option<u32>,
    pub sub_filter: Option<String>,
    /// A document timestamp, not a signature by a person.
    pub doc_timestamp: bool,
    /// Common name of the signer certificate; the signature's `/Name` when the certificate
    /// cannot be read.
    pub signer: Option<String>,
    /// `/M` as an RFC 3339 time when it parses, as written in the file otherwise.
    pub signed_at: Option<String>,
    pub reason: Option<String>,
    pub location: Option<String>,
    /// 1-based number of the revision the signature covers.
    pub revision: usize,
    /// What is wrong with this signature. Empty when it is intact.
    pub status: Vec<ValidityError>,
}

impl SignatureInfo {
    pub fn is_intact(&self) -> bool {
        self.status.is_empty()
    }
}

impl Report {
    /// The verdict list is exactly `[OK]`.
    pub fn is_ok(&self) -> bool {
        self.verdicts == [Verdict::OK]
    }

    /// The report as indented JSON, the form `sealpdf ls --json` and the app's library share.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a report always serializes")
    }
}
