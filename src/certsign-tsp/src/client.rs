use crate::{
    asn1::{MessageImprint, TimeStampReq, TimeStampResp, TstInfo},
    error::TsaError,
};
use chrono::{DateTime, Utc};
use cms::{content_info::ContentInfo, signed_data::SignedData};
use const_oid::ObjectIdentifier;
use der::{
    Any, Decode, Encode,
    asn1::{BitString, OctetString, Uint},
};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::Extension;

const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// Hash algorithms a time-stamp request may use. SHA-1 is here because some TSAs still need it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsaHash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl TsaHash {
    fn oid(self) -> ObjectIdentifier {
        ObjectIdentifier::new_unwrap(match self {
            Self::Sha1 => "1.3.14.3.2.26",
            Self::Sha256 => "2.16.840.1.101.3.4.2.1",
            Self::Sha384 => "2.16.840.1.101.3.4.2.2",
            Self::Sha512 => "2.16.840.1.101.3.4.2.3",
        })
    }

    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// Parses `SHA-1`, `SHA256`, `sha-512`, ... The default of AutoFirma-compatible requests is SHA-512.
    pub fn from_name(name: &str) -> Option<Self> {
        let n: String = name
            .chars()
            .filter(|c| *c != '-')
            .collect::<String>()
            .to_ascii_uppercase();
        match n.as_str() {
            "SHA1" => Some(Self::Sha1),
            "SHA256" => Some(Self::Sha256),
            "SHA384" => Some(Self::Sha384),
            "SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// A request extension. Its value is the DER the TSA expects, already encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsaExtension {
    pub oid: String,
    pub critical: bool,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsaRequest {
    pub hash: TsaHash,
    /// Digest of the data to stamp, made with `hash`.
    pub digest: Vec<u8>,
    /// Requested policy, as a dotted OID.
    pub policy: Option<String>,
    /// Nonce to send; the response must echo it. `HttpTransport` users normally set one
    /// with [`TsaRequest::with_random_nonce`].
    pub nonce: Option<u64>,
    /// Ask the TSA to include its certificate.
    pub cert_req: bool,
    pub extension: Option<TsaExtension>,
}

impl TsaRequest {
    /// A request for the digest of `data`, asking for the TSA certificate and sending no policy or nonce.
    pub fn for_data(hash: TsaHash, data: &[u8]) -> Self {
        Self {
            hash,
            digest: hash.hash(data),
            policy: None,
            nonce: None,
            cert_req: true,
            extension: None,
        }
    }

    #[cfg(feature = "http")]
    pub fn with_random_nonce(mut self) -> Self {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("system randomness");
        // Keep it positive and non-zero so every implementation encodes it the same way.
        self.nonce = Some((u64::from_be_bytes(bytes) >> 1).max(1));
        self
    }
}

/// A granted time-stamp token, checked against the request that asked for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampToken {
    /// DER of the token, a CMS `ContentInfo` holding the signed `TSTInfo`.
    pub der: Vec<u8>,
    pub gen_time: DateTime<Utc>,
    /// Policy the TSA stamped under, as a dotted OID.
    pub policy: String,
    pub serial_number: Vec<u8>,
}

/// Moves bytes to a TSA and back: HTTP in production, recorded exchanges in tests.
pub trait Transport {
    /// Sends the DER `TimeStampReq` and returns the DER `TimeStampResp`.
    fn send(&self, request_der: &[u8]) -> Result<Vec<u8>, TsaError>;

    /// What to call the TSA in error messages.
    fn name(&self) -> String;
}

/// Builds requests, sends them through a [`Transport`] and checks what comes back.
pub struct TsaClient<T> {
    transport: T,
}

fn status_name(status: u8) -> &'static str {
    match status {
        0 => "granted",
        1 => "grantedWithMods",
        2 => "rejection",
        3 => "waiting",
        4 => "revocationWarning",
        5 => "revocationNotification",
        _ => "unknown",
    }
}

/// Names of the `PKIFailureInfo` bits (RFC 3161 section 2.4.2) that are set.
fn fail_reasons(bits: &BitString) -> Vec<&'static str> {
    const NAMES: [(usize, &str); 8] = [
        (0, "badAlg"),
        (2, "badRequest"),
        (5, "badDataFormat"),
        (14, "timeNotAvailable"),
        (15, "unacceptedPolicy"),
        (16, "unacceptedExtension"),
        (17, "addInfoNotAvailable"),
        (25, "systemFailure"),
    ];
    let raw = bits.raw_bytes();
    NAMES
        .iter()
        .filter(|(bit, _)| {
            raw.get(bit / 8)
                .is_some_and(|byte| byte & (0x80 >> (bit % 8)) != 0)
        })
        .map(|(_, name)| *name)
        .collect()
}

impl<T: Transport> TsaClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Encodes `req` as a DER `TimeStampReq`.
    pub fn encode_request(req: &TsaRequest) -> Result<Vec<u8>, TsaError> {
        let bad = |what: &str, e: &dyn std::fmt::Display| TsaError::Malformed {
            url: String::new(),
            reason: format!("{what}: {e}"),
        };
        if req.digest.len() != req.hash.digest_len() {
            return Err(bad(
                "digest",
                &format!("{} bytes for {:?}", req.digest.len(), req.hash),
            ));
        }
        let extensions = match &req.extension {
            None => None,
            Some(ext) => Some(vec![Extension {
                extn_id: ObjectIdentifier::new(&ext.oid).map_err(|e| bad("extension OID", &e))?,
                critical: ext.critical,
                extn_value: OctetString::new(ext.value.clone())
                    .map_err(|e| bad("extension value", &e))?,
            }]),
        };
        let policy = req
            .policy
            .as_deref()
            .map(|p| ObjectIdentifier::new(p).map_err(|e| bad("policy OID", &e)))
            .transpose()?;
        let nonce = req
            .nonce
            .map(|n| Uint::new(&n.to_be_bytes()).map_err(|e| bad("nonce", &e)))
            .transpose()?;
        let message = TimeStampReq {
            version: 1,
            message_imprint: MessageImprint {
                hash_algorithm: AlgorithmIdentifierOwned {
                    oid: req.hash.oid(),
                    parameters: Some(Any::new(der::Tag::Null, Vec::new()).expect("NULL")),
                },
                hashed_message: OctetString::new(req.digest.clone())
                    .map_err(|e| bad("digest", &e))?,
            },
            req_policy: policy,
            nonce,
            cert_req: req.cert_req,
            extensions,
        };
        message.to_der().map_err(|e| bad("encoding", &e))
    }

    /// Asks the TSA for a time-stamp and checks the answer: granted status, a token whose
    /// message imprint, nonce and policy match the request.
    pub fn request(&self, req: &TsaRequest) -> Result<TimestampToken, TsaError> {
        let url = self.transport.name();
        let encoded = Self::encode_request(req).map_err(|e| match e {
            TsaError::Malformed { reason, .. } => TsaError::Malformed {
                url: url.clone(),
                reason,
            },
            other => other,
        })?;
        let answer = self.transport.send(&encoded)?;
        check_response(&url, req, &answer)
    }
}

/// Validates the `TimeStampResp` in `answer` against `req`.
pub(crate) fn check_response(
    url: &str,
    req: &TsaRequest,
    answer: &[u8],
) -> Result<TimestampToken, TsaError> {
    let malformed = |reason: String| TsaError::Malformed {
        url: url.to_owned(),
        reason,
    };
    let resp = TimeStampResp::from_der(answer)
        .map_err(|e| malformed(format!("not a TimeStampResp: {e}")))?;

    let status = resp.status.status;
    if status > 1 {
        let mut detail = String::new();
        if let Some(text) = resp
            .status
            .status_string
            .as_ref()
            .and_then(|s| s.decode_as::<Vec<Any>>().ok())
        {
            let joined: Vec<String> = text
                .iter()
                .map(|t| String::from_utf8_lossy(t.value()).into_owned())
                .collect();
            if !joined.is_empty() {
                detail.push_str(&format!(": {}", joined.join("; ")));
            }
        }
        if let Some(info) = &resp.status.fail_info {
            let reasons = fail_reasons(info);
            if !reasons.is_empty() {
                detail.push_str(&format!(" [{}]", reasons.join(", ")));
            }
        }
        return Err(TsaError::Rejected {
            url: url.to_owned(),
            status,
            name: status_name(status),
            detail,
        });
    }

    let token = resp
        .time_stamp_token
        .ok_or_else(|| malformed("status is granted but there is no token".into()))?;
    let token_der = token.to_der().map_err(|e| malformed(e.to_string()))?;
    let info = ContentInfo::from_der(&token_der).map_err(|e| malformed(format!("token: {e}")))?;
    if info.content_type != ID_SIGNED_DATA {
        return Err(malformed("the token is not a CMS SignedData".into()));
    }
    let signed: SignedData = info
        .content
        .decode_as()
        .map_err(|e| malformed(format!("token: {e}")))?;
    if signed.encap_content_info.econtent_type != ID_CT_TST_INFO {
        return Err(malformed("the token does not contain a TSTInfo".into()));
    }
    let tst_bytes = signed
        .encap_content_info
        .econtent
        .ok_or_else(|| malformed("the token has no content".into()))?
        .decode_as::<OctetString>()
        .map_err(|e| malformed(format!("TSTInfo: {e}")))?;
    let tst =
        TstInfo::from_der(tst_bytes.as_bytes()).map_err(|e| malformed(format!("TSTInfo: {e}")))?;

    let imprint = &tst.message_imprint;
    if imprint.hash_algorithm.oid != req.hash.oid()
        || imprint.hashed_message.as_bytes() != req.digest.as_slice()
    {
        return Err(TsaError::ImprintMismatch {
            url: url.to_owned(),
        });
    }
    if let Some(sent) = req.nonce {
        let echoed = tst.nonce.as_ref().map(|n| n.as_bytes());
        let expected = Uint::new(&sent.to_be_bytes()).map_err(|e| malformed(e.to_string()))?;
        if echoed != Some(expected.as_bytes()) {
            return Err(TsaError::NonceMismatch {
                url: url.to_owned(),
            });
        }
    }
    if let Some(wanted) = &req.policy {
        let wanted_oid = ObjectIdentifier::new(wanted).map_err(|e| malformed(e.to_string()))?;
        if tst.policy != wanted_oid {
            return Err(TsaError::PolicyMismatch {
                url: url.to_owned(),
                wanted: wanted.clone(),
                got: tst.policy.to_string(),
            });
        }
    }

    let secs = i64::try_from(tst.gen_time.to_unix_duration().as_secs())
        .map_err(|_| malformed("genTime".into()))?;
    let nanos = tst.gen_time.to_unix_duration().subsec_nanos();
    let gen_time = DateTime::from_timestamp(secs, nanos)
        .ok_or_else(|| malformed("genTime out of range".into()))?;
    Ok(TimestampToken {
        der: token_der,
        gen_time,
        policy: tst.policy.to_string(),
        serial_number: tst.serial_number.as_bytes().to_vec(),
    })
}
