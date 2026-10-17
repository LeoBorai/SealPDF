//! The production [`Transport`]: time-stamp requests over HTTP or HTTPS.
//!
//! A TSA is a web service (RFC 3161 section 3.4). A request is a `POST` of the DER
//! `TimeStampReq` with content type `application/timestamp-query`; the answer is a DER
//! `TimeStampResp`. This module does that exchange and nothing else: building requests and
//! checking answers is done by [`crate::TsaClient`], which only knows the [`Transport`] trait.
//!
//! What [`HttpTransport`] adds over a bare `POST`:
//!
//! - HTTP Basic credentials, never shown by `Debug`;
//! - a 30 second timeout and a 4 MiB cap on the response body;
//! - HTTP error statuses reported as [`TsaError::Http`] with the TSA's URL;
//! - a retry, up to three times, when a signal interrupts the call;
//! - the platform trust roots for HTTPS. TLS client certificates are not supported.
//!
//! This module is built only with the `http` cargo feature (on by default), which is also what
//! pulls in the `ureq` and `getrandom` dependencies. Without the feature the crate has no network
//! dependency and callers supply their own [`Transport`].

use crate::{Transport, TsaError};
use std::{io::Read, time::Duration};

const MAX_RESPONSE: u64 = 4 * 1024 * 1024;

/// Talks to a TSA over HTTP or HTTPS (RFC 3161 section 3.4), with optional Basic credentials.
///
/// The platform trust roots are used for HTTPS; TLS client certificates are not supported.
pub struct HttpTransport {
    url: String,
    credentials: Option<(String, String)>,
    agent: ureq::Agent,
}

impl HttpTransport {
    pub fn new(url: impl Into<String>) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            // Error statuses are reported by us, with the TSA's URL.
            .http_status_as_error(false)
            .build()
            .into();
        Self {
            url: url.into(),
            credentials: None,
            agent,
        }
    }

    /// HTTP Basic credentials, sent with every request.
    pub fn with_credentials(
        mut self,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.credentials = Some((user.into(), password.into()));
        self
    }
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("url", &self.url)
            .field(
                "credentials",
                &self.credentials.as_ref().map(|(u, _)| (u, "<redacted>")),
            )
            .finish()
    }
}

fn basic(user: &str, password: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = format!("{user}:{password}").into_bytes();
    let mut out = String::from("Basic ");
    for chunk in raw.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

impl Transport for HttpTransport {
    fn send(&self, request_der: &[u8]) -> Result<Vec<u8>, TsaError> {
        let mut attempts = 0;
        let mut response = loop {
            let mut request = self
                .agent
                .post(&self.url)
                .header("Content-Type", "application/timestamp-query")
                .header("Accept", "application/timestamp-reply");
            if let Some((user, password)) = &self.credentials {
                request = request.header("Authorization", basic(user, password));
            }
            match request.send(request_der) {
                Ok(response) => break response,
                // A signal (a child process exiting, say) can interrupt the call: try again.
                Err(ureq::Error::Io(e))
                    if e.kind() == std::io::ErrorKind::Interrupted && attempts < 3 =>
                {
                    attempts += 1;
                }
                Err(e) => {
                    return Err(TsaError::Unreachable {
                        url: self.url.clone(),
                        reason: e.to_string(),
                    });
                }
            }
        };
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(TsaError::Http {
                url: self.url.clone(),
                status,
            });
        }
        let mut body = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(MAX_RESPONSE)
            .read_to_end(&mut body)
            .map_err(|e| TsaError::Unreachable {
                url: self.url.clone(),
                reason: format!("reading the response: {e}"),
            })?;
        Ok(body)
    }

    fn name(&self) -> String {
        self.url.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::basic;

    #[test]
    fn basic_auth_header() {
        assert_eq!(
            basic("Aladdin", "open sesame"),
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
        assert_eq!(basic("a", "b"), "Basic YTpi");
        assert_eq!(basic("ab", "c"), "Basic YWI6Yw==");
        assert_eq!(basic("", ""), "Basic Og==");
    }
}
