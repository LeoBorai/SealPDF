use certsign_core::{Error, ErrorCode};

/// The exit codes of `certsign`.
pub const OK: i32 = 0;
/// A problem with how the command was called. Also what `clap` exits with.
pub const USAGE: i32 = 2;
/// Signing was refused by a pre-sign rule: encrypted, certified or unreadable PDF.
pub const REFUSED: i32 = 3;
/// A key store, password or key access problem.
pub const KEYSTORE: i32 = 4;
/// Anything else.
pub const OTHER: i32 = 6;

/// A failure of a command, with the exit code it ends the program with.
#[derive(Debug)]
pub struct Failure {
    pub code: i32,
    pub message: String,
}

impl Failure {
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            code: USAGE,
            message: message.into(),
        }
    }

    pub fn other(message: impl Into<String>) -> Self {
        Self {
            code: OTHER,
            message: message.into(),
        }
    }
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        Self {
            code: code_of(&e),
            message: e.to_string(),
        }
    }
}

/// The one place that maps errors to exit codes.
pub fn code_of(e: &Error) -> i32 {
    match e {
        Error::Keystore(_) => KEYSTORE,
        // Refusals: the document was turned away before anything was signed.
        Error::Refused(_) | Error::InvalidPdf(_) => REFUSED,
        Error::Pdf(code) if is_refusal(code) => REFUSED,
        _ => OTHER,
    }
}

fn is_refusal(code: &ErrorCode) -> bool {
    [
        ErrorCode::PDF_CERTIFIED,
        ErrorCode::PDF_PASSWORD_REQUIRED,
        ErrorCode::PDF_BAD_PASSWORD,
        ErrorCode::PDF_FORM_MODIFIED,
        ErrorCode::PDF_WITH_UNREGISTERED_SIGNATURES,
        ErrorCode::PDF_SUSPECTED_PSA,
        ErrorCode::PDF_DOCUMENT_NEEDED,
    ]
    .contains(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use certsign_core::KeystoreError;

    #[test]
    fn maps_errors_to_codes() {
        assert_eq!(code_of(&KeystoreError::BadPassword.into()), KEYSTORE);
        assert_eq!(
            code_of(&KeystoreError::AccessDenied("no".into()).into()),
            KEYSTORE
        );
        assert_eq!(
            code_of(&KeystoreError::UnknownAlias("x".into()).into()),
            KEYSTORE
        );
        assert_eq!(code_of(&ErrorCode::PDF_CERTIFIED.into()), REFUSED);
        assert_eq!(code_of(&ErrorCode::PDF_PASSWORD_REQUIRED.into()), REFUSED);
        assert_eq!(code_of(&Error::Refused("encrypted".into())), REFUSED);
        assert_eq!(code_of(&Error::InvalidPdf("junk".into())), REFUSED);
        assert_eq!(
            code_of(&Error::SignatureTooLarge {
                needed: 2,
                reserved: 1
            }),
            OTHER
        );
        assert_eq!(code_of(&Error::Other("x".into())), OTHER);
        assert_eq!(code_of(&Error::UnsupportedAlgorithm("x".into())), OTHER);
    }
}
