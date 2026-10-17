use serde::Serialize;

pub type Result<T> = std::result::Result<T, Error>;

/// Numeric error code with its human-readable description.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ErrorCode {
    pub code: &'static str,
    pub description: &'static str,
}

impl ErrorCode {
    pub const UNKNOWN_PADES_SIGNING_ERROR: Self =
        Self::new("212001", "Unknown error generating the PAdES signature");
    pub const INTERNAL_PADES_SIGNING_ERROR: Self =
        Self::new("212002", "Internal error generating the PAdES signature");
    pub const PDF_WITH_UNREGISTERED_SIGNATURES: Self = Self::new(
        "212003",
        "Attempt to sign a PDF that has unregistered signatures",
    );
    pub const PDF_BAD_PASSWORD: Self = Self::new("212004", "The PDF password is incorrect");
    pub const PDF_PASSWORD_REQUIRED: Self = Self::new("212005", "The PDF requires a password");
    pub const PDF_FORM_MODIFIED: Self = Self::new(
        "212006",
        "Attempt to sign a PDF whose form was modified after a signature",
    );
    pub const PDF_CERTIFIED: Self = Self::new(
        "212007",
        "Attempt to sign a certified PDF that does not allow new signatures",
    );
    pub const PDF_SUSPECTED_PSA: Self = Self::new(
        "212008",
        "Attempt to sign a PDF suspected of modification after signing",
    );
    pub const PDF_DOCUMENT_NEEDED: Self = Self::new(
        "510005",
        "The signature requires the data to be a PDF document",
    );
    pub const INVALID_SIGNATURE_POSITION: Self = Self::new(
        "610301",
        "The position for the visible signature on the page is not valid",
    );
    pub const INVALID_SIGNATURE_PAGE: Self =
        Self::new("610302", "The page for the visible signature is not valid");

    pub const fn new(code: &'static str, description: &'static str) -> Self {
        Self { code, description }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.description)
    }
}

/// Validation failure kinds, named after the identifiers used in verification reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidityError {
    NoData,
    CorruptedSign,
    NoMatchData,
    NoSign,
    CertificateProblem,
    CertificateExpired,
    CertificateNotValidYet,
    CantValidateCert,
    AlgorithmNotSupported,
    CaNotSupported,
    CrlProblem,
    PdfUnknownValidity,
    UnknownError,
    UnknownSignatureFormat,
    ModifiedForm,
    ModifiedDocument,
    OverlappingSignature,
    SuspectedSignature,
}

impl ValidityError {
    /// Stable identifier, as printed in reports and JSON output.
    pub const fn id(self) -> &'static str {
        match self {
            Self::NoData => "NO_DATA",
            Self::CorruptedSign => "CORRUPTED_SIGN",
            Self::NoMatchData => "NO_MATCH_DATA",
            Self::NoSign => "NO_SIGN",
            Self::CertificateProblem => "CERTIFICATE_PROBLEM",
            Self::CertificateExpired => "CERTIFICATE_EXPIRED",
            Self::CertificateNotValidYet => "CERTIFICATE_NOT_VALID_YET",
            Self::CantValidateCert => "CANT_VALIDATE_CERT",
            Self::AlgorithmNotSupported => "ALGORITHM_NOT_SUPPORTED",
            Self::CaNotSupported => "CA_NOT_SUPPORTED",
            Self::CrlProblem => "CRL_PROBLEM",
            Self::PdfUnknownValidity => "PDF_UNKOWN_VALIDITY",
            Self::UnknownError => "UNKOWN_ERROR",
            Self::UnknownSignatureFormat => "UNKOWN_SIGNATURE_FORMAT",
            Self::ModifiedForm => "MODIFIED_FORM",
            Self::ModifiedDocument => "MODIFIED_DOCUMENT",
            Self::OverlappingSignature => "OVERLAPPING_SIGNATURE",
            Self::SuspectedSignature => "SUSPECTED_SIGNATURE",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Pdf(ErrorCode),
    #[error("invalid PDF: {0}")]
    InvalidPdf(String),
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("validity error: {}", .0.id())]
    Validity(ValidityError),
    #[error("signature needs {needed} bytes but only {reserved} are reserved in /Contents")]
    SignatureTooLarge { needed: usize, reserved: usize },
    #[error("invalid options: {0}")]
    Options(String),
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// AutoFirma-compatible numeric code, when the error maps to one.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Pdf(code) => Some(*code),
            Self::InvalidPdf(_) => Some(ErrorCode::PDF_DOCUMENT_NEEDED),
            Self::Other(_) => Some(ErrorCode::UNKNOWN_PADES_SIGNING_ERROR),
            Self::UnsupportedAlgorithm(_)
            | Self::Validity(_)
            | Self::Options(_)
            | Self::SignatureTooLarge { .. } => None,
        }
    }
}

impl From<ErrorCode> for Error {
    fn from(code: ErrorCode) -> Self {
        Self::Pdf(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_error_codes_match_autofirma() {
        let cases = [
            (ErrorCode::PDF_WITH_UNREGISTERED_SIGNATURES, "212003"),
            (ErrorCode::PDF_BAD_PASSWORD, "212004"),
            (ErrorCode::PDF_PASSWORD_REQUIRED, "212005"),
            (ErrorCode::PDF_FORM_MODIFIED, "212006"),
            (ErrorCode::PDF_CERTIFIED, "212007"),
            (ErrorCode::PDF_SUSPECTED_PSA, "212008"),
            (ErrorCode::INVALID_SIGNATURE_POSITION, "610301"),
            (ErrorCode::INVALID_SIGNATURE_PAGE, "610302"),
        ];
        for (code, expected) in cases {
            assert_eq!(Error::from(code).code().unwrap().code, expected);
        }
    }

    #[test]
    fn non_pdf_errors_map_sensibly() {
        assert_eq!(
            Error::InvalidPdf("x".into()).code(),
            Some(ErrorCode::PDF_DOCUMENT_NEEDED)
        );
        assert_eq!(Error::Validity(ValidityError::NoSign).code(), None);
    }

    #[test]
    fn validity_ids_are_stable() {
        assert_eq!(ValidityError::ModifiedDocument.id(), "MODIFIED_DOCUMENT");
        assert_eq!(
            ValidityError::PdfUnknownValidity.id(),
            "PDF_UNKOWN_VALIDITY"
        );
    }

    #[test]
    fn display_includes_code() {
        let e = Error::from(ErrorCode::PDF_CERTIFIED);
        assert!(e.to_string().starts_with("212007"));
    }
}
