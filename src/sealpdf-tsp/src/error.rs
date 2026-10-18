use sealpdf_core::Error;

/// Why a timestamp could not be obtained. Every message names the TSA, when known.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TsaError {
    #[error("{url} cannot be reached: {reason}")]
    Unreachable { url: String, reason: String },
    #[error("{url} answered with HTTP status {status}")]
    Http { url: String, status: u16 },
    #[error("{url} refused the request: status {status} ({name}){detail}")]
    Rejected {
        url: String,
        status: u8,
        name: &'static str,
        /// `: text` from the TSA and the failure reasons, or empty.
        detail: String,
    },
    #[error("{url} returned a time-stamp for different data (message imprint mismatch)")]
    ImprintMismatch { url: String },
    #[error("{url} returned a time-stamp with a different nonce")]
    NonceMismatch { url: String },
    #[error("{url} stamped under policy {got}, not the requested {wanted}")]
    PolicyMismatch {
        url: String,
        wanted: String,
        got: String,
    },
    #[error("{url} sent an unusable response: {reason}")]
    Malformed { url: String, reason: String },
}

impl From<TsaError> for Error {
    fn from(e: TsaError) -> Self {
        Error::Timestamp(e.to_string())
    }
}
