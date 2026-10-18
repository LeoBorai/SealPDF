mod common;

use chrono::{Duration, Utc};
use common::openssl;
use sealpdf_core::{Clock, FixedClock};
use sealpdf_keystore::{CertFilters, Entry};
use std::path::Path;

const DNIE_ISSUER: &str = "/C=ES/O=DIRECCION GENERAL DE LA POLICIA/OU=DNIE/CN=AC DNIE 001";

struct Certs {
    dir: tempfile::TempDir,
}

impl Certs {
    /// `None` when `openssl` is not installed.
    fn new() -> Option<Self> {
        let dir = tempfile::tempdir().unwrap();
        if !openssl(dir.path(), &["version"]) {
            eprintln!("openssl not found: skipping");
            return None;
        }
        Some(Self { dir })
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn ca(&self, name: &str, subject: &str) {
        assert!(openssl(
            self.path(),
            &[
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-subj",
                subject,
                "-days",
                "30",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.pem")
            ]
        ));
    }

    /// A DER certificate issued by CA `ca`. `usage` is the key usage extension value, if any.
    fn leaf(&self, name: &str, ca: &str, subject: &str, usage: Option<&str>, days: u32) -> Vec<u8> {
        let d = self.path();
        let ext = usage
            .map(|u| format!("keyUsage=critical,{u}\n"))
            .unwrap_or_default();
        std::fs::write(d.join(format!("{name}.cnf")), ext).unwrap();
        assert!(openssl(
            d,
            &[
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-subj",
                subject,
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr")
            ]
        ));
        assert!(openssl(
            d,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{name}.csr"),
                "-CA",
                &format!("{ca}.pem"),
                "-CAkey",
                &format!("{ca}.key"),
                "-CAcreateserial",
                "-days",
                &days.to_string(),
                "-extfile",
                &format!("{name}.cnf"),
                "-out",
                &format!("{name}.pem")
            ]
        ));
        assert!(openssl(
            d,
            &[
                "x509",
                "-in",
                &format!("{name}.pem"),
                "-outform",
                "DER",
                "-out",
                &format!("{name}.der")
            ]
        ));
        std::fs::read(d.join(format!("{name}.der"))).unwrap()
    }
}

/// A clock an hour ahead: certificates issued during a test are valid from the moment they are
/// made, so judging them at that very moment can fall just before their notBefore.
fn later() -> FixedClock {
    FixedClock(Utc::now() + Duration::hours(1))
}

fn entry(alias: &str, der: Vec<u8>) -> Entry {
    Entry::new(alias, vec![der]).unwrap()
}

fn aliases(entries: &[Entry]) -> Vec<&str> {
    entries.iter().map(|e| e.alias.as_str()).collect()
}

fn offered(filters: CertFilters, entries: &[Entry], clock: &dyn Clock) -> Vec<String> {
    filters
        .apply(entries.to_vec(), clock)
        .into_iter()
        .map(|e| e.alias)
        .collect()
}

#[test]
fn defaults_are_the_documented_ones() {
    let d = CertFilters::default();
    assert!(
        !d.show_expired && !d.only_signature && !d.only_alias,
        "off by default"
    );
    assert!(d.skip_dnie_auth, "on by default");
}

#[test]
fn expired_certificates_are_hidden_by_default() {
    let Some(c) = Certs::new() else { return };
    c.ca("ca", "/CN=CA");
    let short = c.leaf("short", "ca", "/CN=short", Some("digitalSignature"), 1);
    let long = c.leaf("long", "ca", "/CN=long", Some("digitalSignature"), 30);
    let entries = [entry("short", short), entry("long", long)];
    let now = Utc::now();

    // Both are valid today.
    let today = FixedClock(now);
    assert_eq!(
        offered(CertFilters::default(), &entries, &today),
        ["short", "long"]
    );

    // Two days on, one is expired: only the valid one is offered.
    let later = FixedClock(now + Duration::days(2));
    assert_eq!(offered(CertFilters::default(), &entries, &later), ["long"]);
    // Unless asked to show expired ones.
    let all = CertFilters {
        show_expired: true,
        ..Default::default()
    };
    assert_eq!(offered(all, &entries, &later), ["short", "long"]);

    // A certificate that is not valid yet is hidden too.
    let earlier = FixedClock(now - Duration::days(2));
    assert!(offered(CertFilters::default(), &entries, &earlier).is_empty());
    assert_eq!(offered(all, &entries, &earlier), ["short", "long"]);
}

#[test]
fn validity_bounds_are_inclusive() {
    let Some(c) = Certs::new() else { return };
    c.ca("ca", "/CN=CA");
    let der = c.leaf("one", "ca", "/CN=one", None, 1);
    let parsed = x509_cert::Certificate::from_der_for_test(&der);
    let (from, to) = parsed;
    let f = CertFilters::default();
    assert!(f.matches(&der, from).unwrap(), "valid at notBefore");
    assert!(f.matches(&der, to).unwrap(), "valid at notAfter");
    assert!(!f.matches(&der, from - Duration::seconds(1)).unwrap());
    assert!(!f.matches(&der, to + Duration::seconds(1)).unwrap());
}

trait ValidityOf {
    fn from_der_for_test(der: &[u8]) -> (chrono::DateTime<Utc>, chrono::DateTime<Utc>);
}

impl ValidityOf for x509_cert::Certificate {
    fn from_der_for_test(der: &[u8]) -> (chrono::DateTime<Utc>, chrono::DateTime<Utc>) {
        use der::Decode;
        let cert = x509_cert::Certificate::from_der(der).unwrap();
        let v = cert.tbs_certificate().validity();
        let at = |t: x509_cert::time::Time| {
            chrono::DateTime::from_timestamp(t.to_unix_duration().as_secs() as i64, 0).unwrap()
        };
        (at(v.not_before), at(v.not_after))
    }
}

#[test]
fn dnie_authentication_certificate_is_hidden_by_default() {
    let Some(c) = Certs::new() else { return };
    c.ca("dnie", DNIE_ISSUER);
    let auth = c.leaf(
        "auth",
        "dnie",
        "/CN=GARCIA (AUTENTICACION)",
        Some("digitalSignature"),
        5,
    );
    let sign = c.leaf(
        "sign",
        "dnie",
        "/CN=GARCIA (FIRMA)",
        Some("nonRepudiation"),
        5,
    );
    let entries = [
        entry("CertAutenticacion", auth),
        entry("CertFirmaDigital", sign),
    ];
    let now = later();

    assert_eq!(
        offered(CertFilters::default(), &entries, &now),
        ["CertFirmaDigital"]
    );
    let keep = CertFilters {
        skip_dnie_auth: false,
        ..Default::default()
    };
    assert_eq!(
        offered(keep, &entries, &now),
        ["CertAutenticacion", "CertFirmaDigital"]
    );
}

#[test]
fn dnie_filter_needs_every_part_of_the_issuer() {
    let Some(c) = Certs::new() else { return };
    let usage = Some("digitalSignature");
    let issuers = [
        ("real", DNIE_ISSUER, true),
        (
            "lowercase",
            "/C=es/O=direccion general de la policia/OU=dnie/CN=ac dnie 002",
            true,
        ),
        (
            "wrong-cn",
            "/C=ES/O=DIRECCION GENERAL DE LA POLICIA/OU=DNIE/CN=Other CA",
            false,
        ),
        (
            "short-cn",
            "/C=ES/O=DIRECCION GENERAL DE LA POLICIA/OU=DNIE/CN=AC DNIE",
            false,
        ),
        (
            "wrong-ou",
            "/C=ES/O=DIRECCION GENERAL DE LA POLICIA/OU=OTHER/CN=AC DNIE 001",
            false,
        ),
        (
            "wrong-o",
            "/C=ES/O=SOMEONE ELSE/OU=DNIE/CN=AC DNIE 001",
            false,
        ),
        (
            "wrong-c",
            "/C=PT/O=DIRECCION GENERAL DE LA POLICIA/OU=DNIE/CN=AC DNIE 001",
            false,
        ),
        (
            "no-ou",
            "/C=ES/O=DIRECCION GENERAL DE LA POLICIA/CN=AC DNIE 001",
            false,
        ),
    ];
    let now = later();
    for (name, issuer, is_dnie_auth) in issuers {
        c.ca(name, issuer);
        let der = c.leaf(&format!("leaf-{name}"), name, "/CN=leaf", usage, 5);
        let hidden = offered(CertFilters::default(), &[entry(name, der)], &now).is_empty();
        assert_eq!(hidden, is_dnie_auth, "{name}: {issuer}");
    }
}

#[test]
fn dnie_filter_depends_on_the_key_usage() {
    let Some(c) = Certs::new() else { return };
    c.ca("dnie", DNIE_ISSUER);
    let now = later();
    let cases = [
        (Some("digitalSignature"), true),
        // Only digitalSignature is required, so a certificate that also has
        // nonRepudiation counts as an authentication certificate and is skipped as well.
        (Some("digitalSignature,nonRepudiation"), true),
        (Some("nonRepudiation"), false),
        (Some("keyEncipherment"), false),
        // No key usage extension at all is not an authentication certificate.
        (None, false),
    ];
    for (i, (usage, skipped)) in cases.into_iter().enumerate() {
        let der = c.leaf(&format!("k{i}"), "dnie", "/CN=leaf", usage, 5);
        let hidden = offered(CertFilters::default(), &[entry("e", der)], &now).is_empty();
        assert_eq!(hidden, skipped, "{usage:?}");
    }
}

#[test]
fn only_signature_certificates() {
    let Some(c) = Certs::new() else { return };
    c.ca("ca", "/CN=CA");
    let now = later();
    let entries = [
        entry(
            "sign",
            c.leaf("a", "ca", "/CN=a", Some("nonRepudiation"), 5),
        ),
        entry(
            "auth",
            c.leaf("b", "ca", "/CN=b", Some("digitalSignature"), 5),
        ),
        entry(
            "both",
            c.leaf(
                "c",
                "ca",
                "/CN=c",
                Some("digitalSignature,nonRepudiation"),
                5,
            ),
        ),
        entry("none", c.leaf("d", "ca", "/CN=d", None, 5)),
    ];
    let only = CertFilters {
        only_signature: true,
        ..Default::default()
    };
    assert_eq!(offered(only, &entries, &now), ["sign", "both"]);
    // Off by default: nothing is dropped for its usage.
    assert_eq!(
        offered(CertFilters::default(), &entries, &now),
        ["sign", "auth", "both", "none"]
    );
}

#[test]
fn only_pseudonym_certificates() {
    let Some(c) = Certs::new() else { return };
    c.ca("ca", "/CN=CA");
    let now = later();
    let entries = [
        entry(
            "alias",
            c.leaf(
                "p",
                "ca",
                "/CN=Persona/pseudonym=jperez",
                Some("nonRepudiation"),
                5,
            ),
        ),
        entry(
            "real",
            c.leaf(
                "r",
                "ca",
                "/CN=PEREZ GARCIA JUAN - 12345678Z",
                Some("nonRepudiation"),
                5,
            ),
        ),
    ];
    let only = CertFilters {
        only_alias: true,
        ..Default::default()
    };
    assert_eq!(offered(only, &entries, &now), ["alias"]);
    assert_eq!(
        offered(CertFilters::default(), &entries, &now),
        ["alias", "real"]
    );
}

#[test]
fn filters_combine_with_and() {
    let Some(c) = Certs::new() else { return };
    c.ca("ca", "/CN=CA");
    c.ca("dnie", DNIE_ISSUER);
    let now = Utc::now();
    let entries = [
        // Passes everything.
        entry(
            "good",
            c.leaf("g", "ca", "/CN=g/pseudonym=x", Some("nonRepudiation"), 30),
        ),
        // Expires first.
        entry(
            "expiring",
            c.leaf("e", "ca", "/CN=e/pseudonym=x", Some("nonRepudiation"), 1),
        ),
        // Wrong usage.
        entry(
            "auth-usage",
            c.leaf("u", "ca", "/CN=u/pseudonym=x", Some("digitalSignature"), 30),
        ),
        // No pseudonym.
        entry(
            "plain",
            c.leaf("p", "ca", "/CN=p", Some("nonRepudiation"), 30),
        ),
        // A DNIe authentication certificate with a pseudonym.
        entry(
            "dnie-auth",
            c.leaf(
                "d",
                "dnie",
                "/CN=d/pseudonym=x",
                Some("digitalSignature"),
                30,
            ),
        ),
    ];
    let strict = CertFilters {
        show_expired: false,
        only_signature: true,
        only_alias: true,
        skip_dnie_auth: true,
    };
    let later = FixedClock(now + Duration::days(2));
    assert_eq!(offered(strict, &entries, &later), ["good"]);
}

#[test]
fn apply_keeps_order_and_drops_unreadable_entries() {
    let Some(c) = Certs::new() else { return };
    c.ca("ca", "/CN=CA");
    let now = later();
    let mk = |n: &str| {
        entry(
            n,
            c.leaf(n, "ca", &format!("/CN={n}"), Some("nonRepudiation"), 5),
        )
    };
    let entries = vec![
        mk("c"),
        Entry::new("broken", vec![b"not a certificate".to_vec()]).unwrap(),
        mk("a"),
        mk("b"),
    ];
    let out = CertFilters::default().apply(entries, &now);
    assert_eq!(aliases(&out), ["c", "a", "b"]);
}

#[test]
fn matches_reports_unreadable_certificates() {
    let err = CertFilters::default()
        .matches(b"garbage", Utc::now())
        .unwrap_err();
    assert!(err.to_string().contains("unreadable certificate"), "{err}");
}
