mod common;

use assert_cmd::Command;
use common::{Leaf, Pki, blank_pdf, certified_pdf};
use predicates::prelude::*;
use sealpdf_cms::verify_detached;
use std::path::{Path, PathBuf};

const PASSWORD: &str = "s3kret-pw";

fn sealpdf() -> Command {
    let mut cmd = Command::cargo_bin("sealpdf").unwrap();
    // Never inherit a password from the environment running the tests. Standard input is not a
    // terminal when a command's output is captured.
    cmd.env_remove("SEALPDF_PW");
    cmd
}

/// A `.p12` with `leaf` in it, and the `--keystore` argument for it.
fn p12(pki: &Pki, leaf: &Leaf) -> String {
    format!("pkcs12:{}", pki.p12(leaf, PASSWORD, &[]).display())
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

/// The byte range, CMS and covered bytes of the `n`th signature in a file.
fn verify_nth(file: &[u8], n: usize) -> sealpdf_cms::VerifiedSignature {
    let pdf = sealpdf_pdf::PdfDocument::open(file.to_vec(), None).unwrap();
    let r = pdf.signatures()[n]
        .value
        .as_ref()
        .unwrap()
        .byte_range
        .clone()
        .unwrap();
    let (a, b, c) = (r[1] as usize, r[2] as usize, r[3] as usize);
    let hex = std::str::from_utf8(&file[a + 1..b - 1]).unwrap();
    let cms: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    let covered = [&file[..a], &file[b..b + c]].concat();
    verify_detached(&cms, &covered).unwrap()
}

// ---- usage and help

#[test]
fn help_and_version() {
    sealpdf()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("list-certs").and(predicate::str::contains("sign")));
    sealpdf()
        .args(["sign", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("--keystore")
                .and(predicate::str::contains("--alias"))
                .and(predicate::str::contains("--force"))
                .and(predicate::str::contains("--password-env")),
        );
    sealpdf()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("sealpdf"));
}

#[test]
fn usage_errors_exit_with_2() {
    sealpdf().assert().code(2);
    sealpdf().arg("nonsense").assert().code(2);
    sealpdf().arg("sign").assert().code(2); // no input
    sealpdf()
        .args(["list-certs", "--keystore", "windows:"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("keychain").and(predicate::str::contains("pkcs12")));
    sealpdf()
        .args(["list-certs", "--keystore", "pkcs12:"])
        .assert()
        .code(2);
}

#[test]
fn secrets_are_never_arguments() {
    for flag in ["--password", "--pin", "--password-value"] {
        sealpdf()
            .args(["list-certs", "--keystore", "pkcs12:x.p12", flag, "hunter2"])
            .assert()
            .code(2);
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn without_a_default_keystore_one_is_required() {
    sealpdf()
        .arg("list-certs")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--keystore is required"));
}

// ---- list-certs

#[test]
fn lists_a_pkcs12_certificate() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("Ada Lovelace", None);
    sealpdf()
        .args([
            "list-certs",
            "--keystore",
            &p12(&pki, &leaf),
            "--password-env",
            "SEALPDF_PW",
        ])
        .env("SEALPDF_PW", PASSWORD)
        .assert()
        .success()
        .stdout(
            predicate::str::starts_with("ALIAS")
                .and(predicate::str::contains("Ada Lovelace"))
                .and(predicate::str::contains("Intermediate CA"))
                .and(predicate::str::contains(" to ")),
        )
        // The result goes to stdout alone.
        .stderr(predicate::str::is_empty());
}

#[test]
fn an_expired_certificate_is_not_listed() {
    let Some(pki) = Pki::new() else { return };
    // A certificate whose validity ended in 2021: needs OpenSSL 3.4 or later to make.
    let d = pki.path();
    let made = common::openssl(
        d,
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-subj",
            "/CN=Old Cert",
            "-not_before",
            "20200101000000Z",
            "-not_after",
            "20210101000000Z",
            "-keyout",
            "old.key",
            "-out",
            "old.pem",
        ],
    );
    if !made {
        eprintln!("this OpenSSL cannot make an expired certificate: skipping");
        return;
    }
    assert!(common::openssl(
        d,
        &[
            "pkcs12",
            "-export",
            "-inkey",
            "old.key",
            "-in",
            "old.pem",
            "-name",
            "old",
            "-passout",
            &format!("pass:{PASSWORD}"),
            "-out",
            "old.p12"
        ]
    ));
    sealpdf()
        .args([
            "list-certs",
            "--keystore",
            &format!("pkcs12:{}", d.join("old.p12").display()),
            "--password-env",
            "SEALPDF_PW",
        ])
        .env("SEALPDF_PW", PASSWORD)
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("No signing certificates"));
}

#[test]
fn password_problems_exit_with_4() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let ks = p12(&pki, &leaf);
    // Wrong password.
    sealpdf()
        .args([
            "list-certs",
            "--keystore",
            &ks,
            "--password-env",
            "SEALPDF_PW",
        ])
        .env("SEALPDF_PW", "wrong")
        .assert()
        .code(4)
        .stderr(predicate::str::contains("wrong password"));
    // The variable is not set.
    sealpdf()
        .args([
            "list-certs",
            "--keystore",
            &ks,
            "--password-env",
            "SEALPDF_PW",
        ])
        .assert()
        .code(4);
    // No terminal and no variable named: the error explains the option.
    sealpdf()
        .args(["list-certs", "--keystore", &ks])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("--password-env"));
    // A file that is not there.
    sealpdf()
        .args([
            "list-certs",
            "--keystore",
            "pkcs12:/nonexistent/x.p12",
            "--password-env",
            "SEALPDF_PW",
        ])
        .env("SEALPDF_PW", PASSWORD)
        .assert()
        .code(4);
}

// ---- sign

#[test]
fn signs_a_pdf_next_to_the_input() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let dir = tempfile::tempdir().unwrap();
    let pdf = blank_pdf(2, false);
    let input = write(dir.path(), "contract.pdf", &pdf);

    sealpdf()
        .args([
            "sign",
            input.to_str().unwrap(),
            "--keystore",
            &p12(&pki, &leaf),
            "--password-env",
            "SEALPDF_PW",
        ])
        .env("SEALPDF_PW", PASSWORD)
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("contract_signed.pdf"));

    assert_eq!(
        std::fs::read(&input).unwrap(),
        pdf,
        "the input is unchanged"
    );
    let signed = std::fs::read(dir.path().join("contract_signed.pdf")).unwrap();
    assert_eq!(signed[..pdf.len()], pdf[..]);
    assert_eq!(verify_nth(&signed, 0).signer, leaf.cert_der);
    // No temporary file is left behind.
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
}

#[test]
fn signs_to_a_named_output() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let dir = tempfile::tempdir().unwrap();
    let input = write(dir.path(), "in.pdf", &blank_pdf(1, false));
    let out = dir.path().join("out.pdf");
    sealpdf()
        .args([
            "sign",
            input.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--keystore",
            &p12(&pki, &leaf),
            "--password-env",
            "SEALPDF_PW",
        ])
        .env("SEALPDF_PW", PASSWORD)
        .assert()
        .success();
    assert!(out.exists());
    assert!(!dir.path().join("in_signed.pdf").exists());
}

#[test]
fn never_overwrites_without_force() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let dir = tempfile::tempdir().unwrap();
    let input = write(dir.path(), "a.pdf", &blank_pdf(1, false));
    let existing = write(dir.path(), "a_signed.pdf", b"precious");
    let ks = p12(&pki, &leaf);
    let run = |extra: &[&str]| {
        let mut args = vec![
            "sign",
            input.to_str().unwrap(),
            "--keystore",
            &ks,
            "--password-env",
            "SEALPDF_PW",
        ];
        args.extend_from_slice(extra);
        sealpdf().args(args).env("SEALPDF_PW", PASSWORD).assert()
    };

    run(&[]).code(2).stderr(predicate::str::contains("--force"));
    assert_eq!(std::fs::read(&existing).unwrap(), b"precious", "left alone");

    run(&["--force"]).success();
    assert!(
        std::fs::read(&existing).unwrap().starts_with(b"%PDF-"),
        "replaced with --force"
    );
}

#[test]
fn never_overwrites_the_input() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let dir = tempfile::tempdir().unwrap();
    let pdf = blank_pdf(1, false);
    let input = write(dir.path(), "a.pdf", &pdf);
    let ks = p12(&pki, &leaf);
    for output in [input.clone(), dir.path().join(".").join("a.pdf")] {
        sealpdf()
            .args([
                "sign",
                input.to_str().unwrap(),
                "-o",
                output.to_str().unwrap(),
                "--force",
                "--keystore",
                &ks,
                "--password-env",
                "SEALPDF_PW",
            ])
            .env("SEALPDF_PW", PASSWORD)
            .assert()
            .code(2)
            .stderr(predicate::str::contains("input"));
        assert_eq!(std::fs::read(&input).unwrap(), pdf);
    }
}

#[test]
fn refusals_exit_with_3_and_write_nothing() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let dir = tempfile::tempdir().unwrap();
    let ks = p12(&pki, &leaf);
    let cases = [
        ("certified.pdf", certified_pdf(1), "certified"),
        ("junk.pdf", b"this is not a pdf".to_vec(), "PDF"),
    ];
    for (name, bytes, word) in cases {
        let input = write(dir.path(), name, &bytes);
        sealpdf()
            .args([
                "sign",
                input.to_str().unwrap(),
                "--keystore",
                &ks,
                "--password-env",
                "SEALPDF_PW",
            ])
            .env("SEALPDF_PW", PASSWORD)
            .assert()
            .code(3)
            .stderr(predicate::str::contains(word).or(predicate::str::contains("password")));
        let stem = name.trim_end_matches(".pdf");
        assert!(
            !dir.path().join(format!("{stem}_signed.pdf")).exists(),
            "{name}: nothing written"
        );
    }
    // Only temporary files could be left behind, and none are.
    let count = std::fs::read_dir(dir.path()).unwrap().count();
    assert_eq!(count, 2);
}

#[test]
fn a_missing_input_is_reported() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    sealpdf()
        .args([
            "sign",
            "/nonexistent/x.pdf",
            "--keystore",
            &p12(&pki, &leaf),
            "--password-env",
            "SEALPDF_PW",
        ])
        .env("SEALPDF_PW", PASSWORD)
        .assert()
        .code(6)
        .stderr(predicate::str::contains("/nonexistent/x.pdf"));
}

// ---- choosing the certificate

/// A `.p12` with two key entries, made with the p12-keystore crate.
fn two_entry_p12(pki: &Pki) -> (String, Leaf, Leaf) {
    use p12_keystore::{Certificate, KeyStore as P12, KeyStoreEntry, PrivateKeyChain};
    let (a, b) = (pki.leaf("alice", None), pki.leaf("bob", Some("P-256")));
    let mut p12 = P12::new();
    for leaf in [&a, &b] {
        let chain = vec![
            Certificate::from_der(&leaf.cert_der).unwrap(),
            Certificate::from_der(&pki.intermediate_der()).unwrap(),
        ];
        let key = PrivateKeyChain::new(pki.pkcs8(leaf), leaf.name.as_bytes(), chain);
        p12.add_entry(&leaf.name, KeyStoreEntry::PrivateKeyChain(key));
    }
    let path = pki.path().join("two.p12");
    std::fs::write(&path, p12.writer(PASSWORD).write().unwrap()).unwrap();
    (format!("pkcs12:{}", path.display()), a, b)
}

#[test]
fn several_certificates_need_an_alias_without_a_terminal() {
    let Some(pki) = Pki::new() else { return };
    let (ks, a, b) = two_entry_p12(&pki);
    let dir = tempfile::tempdir().unwrap();
    let input = write(dir.path(), "doc.pdf", &blank_pdf(1, false));
    let run = |extra: &[&str]| {
        let mut args = vec![
            "sign",
            input.to_str().unwrap(),
            "--keystore",
            &ks,
            "--password-env",
            "SEALPDF_PW",
        ];
        args.extend_from_slice(extra);
        sealpdf().args(args).env("SEALPDF_PW", PASSWORD).assert()
    };

    run(&[])
        .code(2)
        .stderr(predicate::str::contains("alice").and(predicate::str::contains("bob")));
    assert!(!dir.path().join("doc_signed.pdf").exists());

    run(&["--alias", "bob"]).success();
    let signed = std::fs::read(dir.path().join("doc_signed.pdf")).unwrap();
    assert_eq!(verify_nth(&signed, 0).signer, b.cert_der);

    run(&["--alias", "alice", "--force"]).success();
    let signed = std::fs::read(dir.path().join("doc_signed.pdf")).unwrap();
    assert_eq!(verify_nth(&signed, 0).signer, a.cert_der);
}

#[test]
fn an_unknown_alias_exits_with_4() {
    let Some(pki) = Pki::new() else { return };
    let (ks, _, _) = two_entry_p12(&pki);
    let dir = tempfile::tempdir().unwrap();
    let input = write(dir.path(), "doc.pdf", &blank_pdf(1, false));
    sealpdf()
        .args([
            "sign",
            input.to_str().unwrap(),
            "--alias",
            "carol",
            "--keystore",
            &ks,
            "--password-env",
            "SEALPDF_PW",
        ])
        .env("SEALPDF_PW", PASSWORD)
        .assert()
        .code(4)
        .stderr(predicate::str::contains("carol"));
    assert!(!dir.path().join("doc_signed.pdf").exists());
}

// ---- secrets and chains

#[test]
fn the_password_never_appears_in_output() {
    let Some(pki) = Pki::new() else { return };
    let leaf = pki.leaf("rsa", None);
    let dir = tempfile::tempdir().unwrap();
    let input = write(dir.path(), "doc.pdf", &blank_pdf(1, false));
    let out = sealpdf()
        .args([
            "--verbose",
            "sign",
            input.to_str().unwrap(),
            "--keystore",
            &p12(&pki, &leaf),
            "--password-env",
            "SEALPDF_PW",
        ])
        .env("SEALPDF_PW", PASSWORD)
        .assert()
        .success();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.get_output().stdout),
        String::from_utf8_lossy(&out.get_output().stderr)
    );
    assert!(!text.contains(PASSWORD), "{text}");
    assert!(
        text.contains("signing with"),
        "--verbose says what it does: {text}"
    );
    // The password is not remembered anywhere: a second run needs it again.
    sealpdf()
        .args([
            "sign",
            input.to_str().unwrap(),
            "--force",
            "--keystore",
            &p12(&pki, &leaf),
            "--password-env",
            "SEALPDF_PW",
        ])
        .assert()
        .code(4);
}

#[test]
fn signing_the_output_again_adds_a_second_signature() {
    let Some(pki) = Pki::new() else { return };
    let (ks, a, b) = two_entry_p12(&pki);
    let dir = tempfile::tempdir().unwrap();
    let input = write(dir.path(), "doc.pdf", &blank_pdf(1, false));
    let run = |input: &Path, alias: &str| {
        sealpdf()
            .args([
                "sign",
                input.to_str().unwrap(),
                "--alias",
                alias,
                "--keystore",
                &ks,
                "--password-env",
                "SEALPDF_PW",
            ])
            .env("SEALPDF_PW", PASSWORD)
            .assert()
            .success();
    };
    run(&input, "alice");
    let first = dir.path().join("doc_signed.pdf");
    run(&first, "bob");
    let second = std::fs::read(dir.path().join("doc_signed_signed.pdf")).unwrap();
    assert_eq!(verify_nth(&second, 0).signer, a.cert_der);
    assert_eq!(verify_nth(&second, 1).signer, b.cert_der);

    if common::pyhanko_available() {
        let sigs = common::pyhanko_validate(pki.path(), &second);
        assert_eq!(sigs.len(), 2);
        assert!(sigs.iter().all(|s| s.intact && s.valid), "{sigs:?}");
    }
}
