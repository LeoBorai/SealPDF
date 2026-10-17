#![doc = include_str!("../README.md")]

mod asn1;
mod client;
mod error;
// Network access, behind the `http` feature. See the module documentation.
#[cfg(feature = "http")]
mod http;
mod recorded;

pub use client::{TimestampToken, Transport, TsaClient, TsaExtension, TsaHash, TsaRequest};
pub use error::TsaError;
#[cfg(feature = "http")]
pub use http::HttpTransport;
pub use recorded::{RecordedTransport, RecordedTsa};

use certsign_core::Result;

/// A time-stamping authority: turns the digest in a request into a signed token.
///
/// Signing code takes a `&dyn Tsa`, so tests can replace the network with [`RecordedTsa`].
pub trait Tsa {
    fn timestamp(&self, request: &TsaRequest) -> Result<TimestampToken>;
}

impl<T: Transport> Tsa for TsaClient<T> {
    fn timestamp(&self, request: &TsaRequest) -> Result<TimestampToken> {
        self.request(request).map_err(Into::into)
    }
}
