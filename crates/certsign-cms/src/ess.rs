//! `SigningCertificateV2` (RFC 5035) as used in the signed attributes.

use der::{Sequence, asn1::OctetString};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    ext::pkix::{certpolicy::PolicyInformation, name::GeneralNames},
    serial_number::SerialNumber,
};

/// ```text
/// IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber CertificateSerialNumber }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct IssuerSerial {
    pub issuer: GeneralNames,
    pub serial_number: SerialNumber,
}

/// ```text
/// ESSCertIDv2 ::= SEQUENCE {
///     hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
///     certHash Hash,
///     issuerSerial IssuerSerial OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct EssCertIdV2 {
    /// Left out for SHA-256, which is the default.
    #[asn1(optional = "true")]
    pub hash_algorithm: Option<AlgorithmIdentifierOwned>,
    pub cert_hash: OctetString,
    #[asn1(optional = "true")]
    pub issuer_serial: Option<IssuerSerial>,
}

/// ```text
/// SigningCertificateV2 ::= SEQUENCE {
///     certs SEQUENCE OF ESSCertIDv2,
///     policies SEQUENCE OF PolicyInformation OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct SigningCertificateV2 {
    pub certs: Vec<EssCertIdV2>,
    #[asn1(optional = "true")]
    pub policies: Option<Vec<PolicyInformation>>,
}
