use crate::{Error, Result, SigAlg};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Signing options, loaded from TOML and layered with CLI flags.
///
/// Every leaf is optional so a file and a set of flags can be layered with
/// [`SignOptions::overlay`]; consumers apply defaults through the accessors.
/// Unknown keys are rejected. Secrets are deliberately not part of the options.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SignOptions {
    pub algorithm: Option<SigAlg>,
    pub metadata: Metadata,
    pub format: Format,
    pub certificate: CertificateOptions,
    pub policy: Policy,
    pub visible: Visible,
    pub certify: Certify,
    pub timestamp: TimestampOptions,
    pub checks: Checks,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Metadata {
    pub reason: Option<String>,
    pub location: Option<String>,
    pub contact: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Format {
    pub subfilter: Option<Subfilter>,
    pub reserved_size: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Subfilter {
    /// `adbe.pkcs7.detached`
    Adbe,
    /// `ETSI.CAdES.detached`
    Etsi,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CertificateOptions {
    pub include_chain: Option<bool>,
    /// Copy the signer certificate's policies into `SigningCertificateV2` (default true).
    pub include_policies: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub identifier: Option<String>,
    pub hash: Option<String>,
    pub hash_algorithm: Option<String>,
    pub qualifier: Option<String>,
    pub commitment_types: Vec<CommitmentType>,
    pub claimed_roles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitmentType {
    pub identifier: String,
    #[serde(default)]
    pub qualifiers: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Visible {
    pub page: Option<Page>,
    pub rect: Option<Rect>,
    pub field: Option<String>,
    pub text: Option<String>,
    pub font_family: Option<String>,
    pub font_size: Option<f32>,
    pub font_style: Option<u32>,
    pub font_color: Option<String>,
    pub image: Option<String>,
    /// Counter-clockwise rotation of the signature content: 0, 90, 180 or 270.
    pub rotation: Option<u32>,
}

/// Target page of a visible signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    /// 1-based page number.
    Number(u32),
    Last,
    /// Add a new page at the end.
    Append,
}

impl<'de> Deserialize<'de> for Page {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u32),
            Name(String),
        }
        match Raw::deserialize(d)? {
            Raw::Num(0) => Err(serde::de::Error::custom("page numbers start at 1")),
            Raw::Num(n) => Ok(Self::Number(n)),
            Raw::Name(s) if s == "last" => Ok(Self::Last),
            Raw::Name(s) if s == "append" => Ok(Self::Append),
            Raw::Name(s) => Err(serde::de::Error::custom(format!(
                "expected a page number, \"last\" or \"append\", got {s:?}"
            ))),
        }
    }
}

impl Serialize for Page {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Number(n) => s.serialize_u32(*n),
            Self::Last => s.serialize_str("last"),
            Self::Append => s.serialize_str("append"),
        }
    }
}

/// Signature rectangle in PDF user space: `[llx, lly, urx, ury]`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(from = "[f32; 4]", into = "[f32; 4]")]
pub struct Rect {
    pub llx: f32,
    pub lly: f32,
    pub urx: f32,
    pub ury: f32,
}

impl From<[f32; 4]> for Rect {
    fn from([llx, lly, urx, ury]: [f32; 4]) -> Self {
        Self { llx, lly, urx, ury }
    }
}

impl From<Rect> for [f32; 4] {
    fn from(r: Rect) -> Self {
        [r.llx, r.lly, r.urx, r.ury]
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Certify {
    pub level: Option<CertLevel>,
}

/// DocMDP certification level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertLevel {
    None,
    /// P=1
    NoChanges,
    /// P=2
    FormFill,
    /// P=3
    Annotate,
}

impl CertLevel {
    /// The DocMDP `/P` value, or `None` when not certifying.
    pub fn docmdp_p(self) -> Option<u8> {
        match self {
            Self::None => None,
            Self::NoChanges => Some(1),
            Self::FormFill => Some(2),
            Self::Annotate => Some(3),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimestampOptions {
    pub mode: Option<TimestampMode>,
    pub url: Option<String>,
    pub policy: Option<String>,
    pub hash_algorithm: Option<String>,
    pub require_cert: Option<bool>,
    pub username: Option<String>,
    pub extension_oid: Option<String>,
    /// Base64 value of the request extension. Needed together with `extension_oid`.
    pub extension_value: Option<String>,
    pub extension_critical: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TimestampMode {
    Signature,
    Document,
    Both,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Checks {
    pub allow_certified: Option<bool>,
    pub allow_unregistered_signatures: Option<bool>,
    pub allow_modified_form: Option<bool>,
    pub allow_shadow_attack: Option<bool>,
    pub shadow_pages: Option<ShadowPages>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowPages {
    All,
    First(u32),
}

impl<'de> Deserialize<'de> for ShadowPages {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u32),
            Name(String),
        }
        match Raw::deserialize(d)? {
            Raw::Num(n) => Ok(Self::First(n)),
            Raw::Name(s) if s == "all" => Ok(Self::All),
            Raw::Name(s) => Err(serde::de::Error::custom(format!(
                "expected a page count or \"all\", got {s:?}"
            ))),
        }
    }
}

impl Serialize for ShadowPages {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::All => s.serialize_str("all"),
            Self::First(n) => s.serialize_u32(*n),
        }
    }
}

impl Serialize for SigAlg {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SigAlg {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

macro_rules! overlay_opts {
    ($dst:expr, $src:expr; $($f:ident),+ $(,)?) => {
        $(if $src.$f.is_some() { $dst.$f = $src.$f.clone(); })+
    };
}

impl SignOptions {
    pub fn from_toml(input: &str) -> Result<Self> {
        toml::from_str(input).map_err(|e| Error::Options(e.message().to_owned()))
    }

    /// Layers `over` on top of `self`: every value set in `over` wins.
    pub fn overlay(&mut self, over: &SignOptions) {
        overlay_opts!(self, over; algorithm);
        overlay_opts!(self.metadata, over.metadata; reason, location, contact);
        overlay_opts!(self.format, over.format; subfilter, reserved_size);
        overlay_opts!(self.certificate, over.certificate; include_chain, include_policies);
        overlay_opts!(self.policy, over.policy; identifier, hash, hash_algorithm, qualifier);
        if !over.policy.commitment_types.is_empty() {
            self.policy.commitment_types = over.policy.commitment_types.clone();
        }
        if !over.policy.claimed_roles.is_empty() {
            self.policy.claimed_roles = over.policy.claimed_roles.clone();
        }
        overlay_opts!(self.visible, over.visible;
            page, rect, field, text, font_family, font_size, font_style, font_color, image, rotation);
        overlay_opts!(self.certify, over.certify; level);
        overlay_opts!(self.timestamp, over.timestamp;
            mode, url, policy, hash_algorithm, require_cert, username,
            extension_oid, extension_value, extension_critical);
        overlay_opts!(self.checks, over.checks;
            allow_certified, allow_unregistered_signatures, allow_modified_form,
            allow_shadow_attack, shadow_pages);
    }

    /// Algorithm to use: the configured one, else `SHA256withRSA`. Signing code picks a default from
    /// the key instead when this is unset (see `sealpdf-pades`).
    pub fn algorithm_or_default(&self) -> SigAlg {
        self.algorithm
            .unwrap_or(SigAlg::new(crate::DigestAlg::Sha256, crate::KeyType::Rsa))
    }

    pub fn subfilter_or_default(&self) -> Subfilter {
        self.format.subfilter.unwrap_or(Subfilter::Adbe)
    }

    /// Reserved `/Contents` size in bytes (default 27000).
    pub fn reserved_size_or_default(&self) -> u32 {
        self.format.reserved_size.unwrap_or(27_000)
    }

    pub fn include_chain_or_default(&self) -> bool {
        self.certificate.include_chain.unwrap_or(true)
    }

    pub fn include_policies_or_default(&self) -> bool {
        self.certificate.include_policies.unwrap_or(true)
    }
}
