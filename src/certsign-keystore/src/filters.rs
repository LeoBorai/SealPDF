//! Which of a key store's certificates are offered for signing.
//!
//! A key store lists every identity it holds, including expired ones and certificates meant for
//! logging in rather than signing. [`CertFilters`] narrows that list with four switches.
//!
//! Filters decide what is *offered*. They do not stop a caller from signing with an alias it
//! names explicitly.

use crate::Entry;
use certsign_core::{Clock, Error, Result};
use chrono::{DateTime, Utc};
use der::{Decode, Tagged, asn1::ObjectIdentifier};
use x509_cert::{
    Certificate,
    ext::pkix::{KeyUsage, KeyUsages},
    name::Name,
};

/// The certificate filter preferences.
///
/// | field | default |
/// | --- | --- |
/// | `show_expired` | `false` |
/// | `only_signature` | `false` |
/// | `only_alias` | `false` |
/// | `skip_dnie_auth` | `true` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertFilters {
    /// Offer certificates outside their validity period (expired or not yet valid).
    pub show_expired: bool,
    /// Offer only certificates whose key usage includes `nonRepudiation`.
    pub only_signature: bool,
    /// Offer only pseudonym certificates: those whose subject has the `pseudonym` attribute.
    pub only_alias: bool,
    /// Leave out the authentication certificate of a Spanish DNIe.
    pub skip_dnie_auth: bool,
}

impl Default for CertFilters {
    fn default() -> Self {
        Self {
            show_expired: false,
            only_signature: false,
            only_alias: false,
            skip_dnie_auth: true,
        }
    }
}

const PSEUDONYM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.65");
const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const COUNTRY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
const ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const ORGANIZATIONAL_UNIT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");

impl CertFilters {
    /// Whether the DER `certificate` passes every enabled filter at the time `now`.
    pub fn matches(&self, certificate: &[u8], now: DateTime<Utc>) -> Result<bool> {
        let cert = Certificate::from_der(certificate)
            .map_err(|e| Error::Other(format!("unreadable certificate: {e}")))?;
        Ok(self.matches_parsed(&cert, now))
    }

    fn matches_parsed(&self, cert: &Certificate, now: DateTime<Utc>) -> bool {
        (self.show_expired || is_valid_at(cert, now))
            && (!self.only_signature || key_usage(cert).is_some_and(|k| k.non_repudiation()))
            && (!self.only_alias || is_pseudonym(cert))
            && (!self.skip_dnie_auth || !is_dnie_authentication(cert))
    }

    /// The entries whose signing certificate passes the filters, judged at the clock's time.
    /// Entries with an unreadable certificate are dropped.
    pub fn apply(&self, entries: Vec<Entry>, clock: &dyn Clock) -> Vec<Entry> {
        let now = clock.now();
        entries
            .into_iter()
            .filter(|e| self.matches(e.certificate(), now).unwrap_or(false))
            .collect()
    }
}

/// `notBefore <= now <= notAfter`, like Java's `checkValidity`.
fn is_valid_at(cert: &Certificate, now: DateTime<Utc>) -> bool {
    let validity = cert.tbs_certificate().validity();
    let secs = |t: x509_cert::time::Time| i64::try_from(t.to_unix_duration().as_secs()).ok();
    match (secs(validity.not_before), secs(validity.not_after)) {
        (Some(from), Some(to)) => (from..=to).contains(&now.timestamp()),
        _ => false,
    }
}

fn key_usage(cert: &Certificate) -> Option<KeyUsageBits> {
    let (_, usage) = cert
        .tbs_certificate()
        .get_extension::<KeyUsage>()
        .ok()
        .flatten()?;
    Some(KeyUsageBits {
        digital_signature: usage.0.contains(KeyUsages::DigitalSignature),
        non_repudiation: usage.0.contains(KeyUsages::NonRepudiation),
    })
}

struct KeyUsageBits {
    digital_signature: bool,
    non_repudiation: bool,
}

impl KeyUsageBits {
    fn non_repudiation(&self) -> bool {
        self.non_repudiation
    }
}

fn is_pseudonym(cert: &Certificate) -> bool {
    cert.tbs_certificate()
        .subject()
        .iter()
        .any(|a| a.oid == PSEUDONYM)
}

/// The text of a directory string attribute value, whatever its string type.
fn text(value: &der::Any) -> Option<String> {
    use der::Tag::{Ia5String, PrintableString, TeletexString, Utf8String};
    matches!(
        value.tag(),
        Utf8String | PrintableString | Ia5String | TeletexString
    )
    .then(|| String::from_utf8_lossy(value.value()).into_owned())
}

/// Whether `name` has an attribute `oid` whose value satisfies `ok`.
fn has(name: &Name, oid: ObjectIdentifier, ok: impl Fn(&str) -> bool) -> bool {
    name.iter()
        .any(|a| a.oid == oid && text(&a.value).is_some_and(|t| ok(&t)))
}

/// The authentication certificate of a DNIe: issued by "AC DNIE ..." of the Spanish police, and
/// able to make digital signatures.
fn is_dnie_authentication(cert: &Certificate) -> bool {
    let issuer = cert.tbs_certificate().issuer();
    let equals = |want: &'static str| move |t: &str| t.eq_ignore_ascii_case(want);
    let dnie_issuer = has(issuer, COMMON_NAME, |t| {
        t.to_ascii_uppercase().starts_with("AC DNIE ")
    }) && has(issuer, ORGANIZATIONAL_UNIT, equals("DNIE"))
        && has(
            issuer,
            ORGANIZATION,
            equals("DIRECCION GENERAL DE LA POLICIA"),
        )
        && has(issuer, COUNTRY, equals("ES"));
    dnie_issuer && key_usage(cert).is_some_and(|k| k.digital_signature)
}
