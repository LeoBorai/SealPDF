use certsign_core::{
    CertLevel, DigestAlg, Error, KeyType, Page, Rect, ShadowPages, SigAlg, SignOptions, Subfilter,
    TimestampMode,
};

const FULL: &str = r#"
algorithm = "SHA256withECDSA"

[metadata]
reason = "Aprobación"
location = "Madrid"
contact = "a@b.es"

[format]
subfilter = "etsi"
reserved_size = 32000

[certificate]
include_chain = false

[policy]
identifier = "2.16.724.1.3.1.1.2.1.9"
hash = "abc="
hash_algorithm = "SHA-256"
qualifier = "https://example.test/policy.pdf"
claimed_roles = ["Director", "Auditor"]

[[policy.commitment_types]]
identifier = "1"
qualifiers = ["1.2.3", "4.5.6"]

[[policy.commitment_types]]
identifier = "2"

[visible]
page = "last"
rect = [10, 20.5, 200, 80]
text = "Firmado por $$SUBJECTCN$$"
font_family = "helvetica"
font_size = 10
font_style = 1
font_color = "black"

[certify]
level = "form-fill"

[timestamp]
mode = "both"
url = "http://tsa.example/ts"
policy = "1.2.3"
require_cert = true
username = "u"

[checks]
allow_shadow_attack = true
shadow_pages = "all"
"#;

#[test]
fn parses_full_config() {
    let o = SignOptions::from_toml(FULL).unwrap();
    assert_eq!(
        o.algorithm,
        Some(SigAlg::new(DigestAlg::Sha256, KeyType::Ecdsa))
    );
    assert_eq!(o.metadata.reason.as_deref(), Some("Aprobación"));
    assert_eq!(o.format.subfilter, Some(Subfilter::Etsi));
    assert_eq!(o.format.reserved_size, Some(32000));
    assert_eq!(o.certificate.include_chain, Some(false));
    assert_eq!(o.policy.claimed_roles, ["Director", "Auditor"]);
    assert_eq!(o.policy.commitment_types.len(), 2);
    assert_eq!(o.policy.commitment_types[0].qualifiers, ["1.2.3", "4.5.6"]);
    assert!(o.policy.commitment_types[1].qualifiers.is_empty());
    assert_eq!(o.visible.page, Some(Page::Last));
    assert_eq!(
        o.visible.rect,
        Some(Rect {
            llx: 10.0,
            lly: 20.5,
            urx: 200.0,
            ury: 80.0
        })
    );
    assert_eq!(o.certify.level, Some(CertLevel::FormFill));
    assert_eq!(o.certify.level.unwrap().docmdp_p(), Some(2));
    assert_eq!(o.timestamp.mode, Some(TimestampMode::Both));
    assert_eq!(o.checks.shadow_pages, Some(ShadowPages::All));
}

#[test]
fn defaults_apply_when_unset() {
    let o = SignOptions::from_toml("").unwrap();
    assert_eq!(o, SignOptions::default());
    assert_eq!(o.algorithm_or_default().to_string(), "SHA512withRSA");
    assert_eq!(o.subfilter_or_default(), Subfilter::Adbe);
    assert_eq!(o.reserved_size_or_default(), 27_000);
    assert!(o.include_chain_or_default());
}

#[test]
fn page_values() {
    let page = |v: &str| {
        SignOptions::from_toml(&format!("[visible]\npage = {v}")).map(|o| o.visible.page.unwrap())
    };
    assert_eq!(page("3").unwrap(), Page::Number(3));
    assert_eq!(page("\"last\"").unwrap(), Page::Last);
    assert_eq!(page("\"append\"").unwrap(), Page::Append);
    assert!(page("0").is_err());
    assert!(page("-1").is_err());
    assert!(page("\"first\"").is_err());
}

#[test]
fn rejects_unknown_keys_naming_them() {
    for (bad, key) in [
        ("bogus = 1", "bogus"),
        ("[metadata]\nreazon = \"x\"", "reazon"),
        ("[timestamp]\npassword = \"secret\"", "password"),
        ("[checks]\nallow_everything = true", "allow_everything"),
    ] {
        let err = SignOptions::from_toml(bad).unwrap_err();
        assert!(matches!(err, Error::Options(_)), "{bad}");
        assert!(err.to_string().contains(key), "{err} should name {key}");
    }
}

#[test]
fn rejects_invalid_values() {
    for bad in [
        "[certify]\nlevel = \"4\"",
        "[timestamp]\nmode = \"sometimes\"",
        "[format]\nsubfilter = \"pkcs7\"",
        "[format]\nreserved_size = -5",
        "algorithm = \"SHA1withRSA\"",
        "[visible]\nrect = [1, 2, 3]",
        "[checks]\nshadow_pages = \"some\"",
    ] {
        assert!(SignOptions::from_toml(bad).is_err(), "{bad}");
    }
}

#[test]
fn flags_override_file() {
    let mut o = SignOptions::from_toml(FULL).unwrap();
    let flags = SignOptions::from_toml(
        "[metadata]\nreason = \"B\"\n[visible]\npage = 2\n[policy]\nclaimed_roles = [\"CEO\"]",
    )
    .unwrap();
    o.overlay(&flags);
    assert_eq!(o.metadata.reason.as_deref(), Some("B"));
    assert_eq!(o.visible.page, Some(Page::Number(2)));
    assert_eq!(o.policy.claimed_roles, ["CEO"]);
    // untouched values survive
    assert_eq!(o.metadata.location.as_deref(), Some("Madrid"));
    assert_eq!(o.policy.commitment_types.len(), 2);
}

#[test]
fn round_trips_through_toml() {
    let o = SignOptions::from_toml(FULL).unwrap();
    let text = toml::to_string(&o).unwrap();
    assert_eq!(SignOptions::from_toml(&text).unwrap(), o);
}

#[test]
fn visible_rotation_is_an_option() {
    let o = SignOptions::from_toml("[visible]\nrotation = 90").unwrap();
    assert_eq!(o.visible.rotation, Some(90));
    let mut base = SignOptions::from_toml("[visible]\nrotation = 90").unwrap();
    base.overlay(&SignOptions::from_toml("[visible]\nrotation = 180").unwrap());
    assert_eq!(base.visible.rotation, Some(180));
}
