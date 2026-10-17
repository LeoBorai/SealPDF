//! ASN.1 structures of RFC 3161.

use der::{
    Any, Sequence,
    asn1::{BitString, GeneralizedTime, ObjectIdentifier, OctetString, Uint},
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::Extension;

/// ```text
/// MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct MessageImprint {
    pub hash_algorithm: AlgorithmIdentifierOwned,
    pub hashed_message: OctetString,
}

/// ```text
/// TimeStampReq ::= SEQUENCE {
///     version INTEGER { v1(1) },
///     messageImprint MessageImprint,
///     reqPolicy TSAPolicyId OPTIONAL,
///     nonce INTEGER OPTIONAL,
///     certReq BOOLEAN DEFAULT FALSE,
///     extensions [0] IMPLICIT Extensions OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct TimeStampReq {
    pub version: u8,
    pub message_imprint: MessageImprint,
    #[asn1(optional = "true")]
    pub req_policy: Option<ObjectIdentifier>,
    #[asn1(optional = "true")]
    pub nonce: Option<Uint>,
    /// Written only when true (the DER default is false).
    #[asn1(default = "default_false")]
    pub cert_req: bool,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<Vec<Extension>>,
}

fn default_false() -> bool {
    false
}

/// ```text
/// PKIStatusInfo ::= SEQUENCE {
///     status PKIStatus, statusString PKIFreeText OPTIONAL, failInfo PKIFailureInfo OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct PkiStatusInfo {
    pub status: u8,
    #[asn1(optional = "true")]
    pub status_string: Option<Any>,
    #[asn1(optional = "true")]
    pub fail_info: Option<BitString>,
}

/// ```text
/// TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct TimeStampResp {
    pub status: PkiStatusInfo,
    #[asn1(optional = "true")]
    pub time_stamp_token: Option<Any>,
}

/// ```text
/// TSTInfo ::= SEQUENCE {
///     version INTEGER, policy TSAPolicyId, messageImprint MessageImprint,
///     serialNumber INTEGER, genTime GeneralizedTime, accuracy Accuracy OPTIONAL,
///     ordering BOOLEAN DEFAULT FALSE, nonce INTEGER OPTIONAL,
///     tsa [0] GeneralName OPTIONAL, extensions [1] IMPLICIT Extensions OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct TstInfo {
    pub version: u8,
    pub policy: ObjectIdentifier,
    pub message_imprint: MessageImprint,
    pub serial_number: Uint,
    pub gen_time: GeneralizedTime,
    #[asn1(optional = "true")]
    pub accuracy: Option<Any>,
    #[asn1(default = "default_false")]
    pub ordering: bool,
    #[asn1(optional = "true")]
    pub nonce: Option<Uint>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub tsa: Option<Any>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<Vec<Extension>>,
}
