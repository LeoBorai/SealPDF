mod common;

use assert_cmd::Command;
use common::{Pki, blank_pdf};
use lopdf::{IncrementalDocument, Object};
use predicates::prelude::*;
use serde_json::Value;
use std::path::{Path, PathBuf};

const PASSWORD: &str = "s3kret-pw";

fn sealpdf() -> Command {
    let mut cmd = Command::cargo_bin("sealpdf").unwrap();
    cmd.env_remove("SEALPDF_PW");
    cmd
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

/// A PDF signed once by "Ada Lovelace" with `sealpdf sign`, and the directory it lives in.
fn signed(pki: &Pki, dir: &Path) -> PathBuf {
    let leaf = pki.leaf("Ada Lovelace", None);
    let keystore = format!("pkcs12:{}", pki.p12(&leaf, PASSWORD, &[]).display());
    let input = write(dir, "contract.pdf", &blank_pdf(1, false));
    sealpdf()
        .args(["sign"])
        .arg(&input)
        .args(["--keystore", &keystore, "--password-env", "SEALPDF_PW"])
        .env("SEALPDF_PW", PASSWORD)
        .assert()
        .success();
    dir.join("contract_signed.pdf")
}

fn tampered(dir: &Path, file: &Path) -> PathBuf {
    let mut bytes = std::fs::read(file).unwrap();
    bytes[7] = b'4'; // the PDF version digit, inside the signed range
    write(dir, "tampered.pdf", &bytes)
}

/// The signed file followed by an update that changes the catalog.
fn changed_after(dir: &Path, file: &Path) -> PathBuf {
    let bytes = std::fs::read(file).unwrap();
    let prev = lopdf::Document::load_mem(&bytes).unwrap();
    let mut inc = IncrementalDocument::create_from(bytes, prev);
    let catalog = inc
        .get_prev_documents()
        .trailer
        .get(b"Root")
        .unwrap()
        .as_reference()
        .unwrap();
    inc.opt_clone_object_to_new_document(catalog).unwrap();
    inc.new_document
        .get_object_mut(catalog)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Lang", Object::string_literal("en"));
    let mut out = Vec::new();
    inc.save_to(&mut out).unwrap();
    write(dir, "changed.pdf", &out)
}

fn json(output: &[u8]) -> Value {
    serde_json::from_slice(output)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(output)))
}

#[test]
fn help_lists_the_new_commands() {
    sealpdf()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("ls").and(predicate::str::contains("verify")));
    sealpdf()
        .args(["verify", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--json"));
}

// ---- ls

#[test]
fn ls_shows_a_signed_pdf() {
    let Some(pki) = Pki::new() else { return };
    let dir = tempfile::tempdir().unwrap();
    let file = signed(&pki, dir.path());
    sealpdf().arg("ls").arg(&file).assert().code(0).stdout(
        predicate::str::contains("Ada Lovelace")
            .and(predicate::str::contains("intact"))
            .and(predicate::str::contains("rev 2 of 2")),
    );
}

#[test]
fn ls_succeeds_on_an_unsigned_pdf() {
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "plain.pdf", &blank_pdf(1, false));
    sealpdf()
        .arg("ls")
        .arg(&file)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("No signatures"));
}

#[test]
fn ls_shows_a_broken_signature_and_still_succeeds() {
    let Some(pki) = Pki::new() else { return };
    let dir = tempfile::tempdir().unwrap();
    let file = tampered(dir.path(), &signed(&pki, dir.path()));
    sealpdf()
        .arg("ls")
        .arg(&file)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("NO_MATCH_DATA"));
}

// ---- verify

#[test]
fn verify_accepts_a_valid_pdf() {
    let Some(pki) = Pki::new() else { return };
    let dir = tempfile::tempdir().unwrap();
    let file = signed(&pki, dir.path());
    sealpdf().arg("verify").arg(&file).assert().code(0).stdout(
        predicate::str::contains("Verdict: OK")
            .and(predicate::str::contains("Ada Lovelace"))
            .and(predicate::str::ends_with(
                "Certificate trust and revocation were not checked.\n",
            )),
    );
}

#[test]
fn verify_rejects_an_unsigned_pdf() {
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "plain.pdf", &blank_pdf(1, false));
    sealpdf()
        .arg("verify")
        .arg(&file)
        .assert()
        .code(5)
        .stdout(predicate::str::contains("Verdict: KO NO_SIGN"))
        .stderr(predicate::str::contains("verification failed"));
}

#[test]
fn verify_rejects_a_broken_signature() {
    let Some(pki) = Pki::new() else { return };
    let dir = tempfile::tempdir().unwrap();
    let file = tampered(dir.path(), &signed(&pki, dir.path()));
    sealpdf()
        .arg("verify")
        .arg(&file)
        .assert()
        .code(5)
        .stdout(predicate::str::contains("Verdict: KO NO_MATCH_DATA"));
}

#[test]
fn verify_does_not_vouch_for_changes_after_the_last_signature() {
    let Some(pki) = Pki::new() else { return };
    let dir = tempfile::tempdir().unwrap();
    let file = changed_after(dir.path(), &signed(&pki, dir.path()));
    sealpdf()
        .arg("verify")
        .arg(&file)
        .assert()
        .code(5)
        .stdout(predicate::str::contains(
            "Verdict: UNKNOWN MODIFIED_DOCUMENT",
        ));
}

// ---- --json

#[test]
fn json_report_of_a_valid_pdf() {
    let Some(pki) = Pki::new() else { return };
    let dir = tempfile::tempdir().unwrap();
    let file = signed(&pki, dir.path());
    for command in ["ls", "verify"] {
        let out = sealpdf()
            .args([command, "--json"])
            .arg(&file)
            .assert()
            .code(0)
            .get_output()
            .stdout
            .clone();
        let report = json(&out);
        assert_eq!(report["verdicts"][0]["verdict"], "OK", "{command}");
        assert_eq!(
            report["signatures"][0]["signer"], "Ada Lovelace",
            "{command}"
        );
        assert_eq!(report["trust_checked"], false, "{command}");
    }
}

#[test]
fn json_report_of_an_unsigned_pdf() {
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "plain.pdf", &blank_pdf(1, false));
    let out = sealpdf()
        .args(["ls", "--json"])
        .arg(&file)
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let report = json(&out);
    assert_eq!(report["signatures"], Value::Array(vec![]));
    assert_eq!(report["verdicts"][0]["verdict"], "KO");
    assert_eq!(report["verdicts"][0]["error"], "NO_SIGN");

    // verify keeps its exit code with --json, and still prints only the report on stdout.
    let out = sealpdf()
        .args(["verify", "--json"])
        .arg(&file)
        .assert()
        .code(5)
        .get_output()
        .stdout
        .clone();
    assert_eq!(json(&out)["verdicts"][0]["error"], "NO_SIGN");
}

// ---- failures

#[test]
fn a_file_that_is_not_a_pdf_exits_3() {
    let dir = tempfile::tempdir().unwrap();
    let file = write(dir.path(), "notes.txt", b"just some text");
    for command in ["ls", "verify"] {
        sealpdf()
            .arg(command)
            .arg(&file)
            .assert()
            .code(3)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains("invalid PDF"));
    }
}

#[test]
fn a_missing_file_exits_6_and_names_it() {
    for command in ["ls", "verify"] {
        sealpdf()
            .args([command, "nowhere/missing.pdf"])
            .assert()
            .code(6)
            .stderr(predicate::str::contains("missing.pdf"));
    }
}

#[test]
fn a_missing_argument_exits_2() {
    sealpdf().arg("ls").assert().code(2);
    sealpdf().arg("verify").assert().code(2);
}

// ---- the reference validator

/// A PDF signed once by `name` with `sealpdf sign`; the key is RSA, or on `curve` when given.
fn signed_by(pki: &Pki, dir: &Path, name: &str, curve: Option<&str>) -> PathBuf {
    let leaf = pki.leaf(name, curve);
    let keystore = format!("pkcs12:{}", pki.p12(&leaf, PASSWORD, &[]).display());
    let input = write(dir, &format!("{name}.pdf"), &blank_pdf(1, false));
    sealpdf()
        .arg("sign")
        .arg(&input)
        .args(["--keystore", &keystore, "--password-env", "SEALPDF_PW"])
        .env("SEALPDF_PW", PASSWORD)
        .assert()
        .success();
    dir.join(format!("{name}_signed.pdf"))
}

/// Our verdict agrees with pyHanko's: `verify` accepts what pyHanko finds intact and valid, and
/// rejects what it does not.
fn agrees_with_pyhanko(pki: &Pki, file: &Path, accepted: bool) {
    let sigs = common::pyhanko_validate(pki.path(), &std::fs::read(file).unwrap());
    assert!(!sigs.is_empty(), "pyHanko found no signature");
    let pyhanko_accepts = sigs.iter().all(|s| s.intact && s.valid);
    assert_eq!(pyhanko_accepts, accepted, "pyHanko says {sigs:?}");
    sealpdf()
        .arg("verify")
        .arg(file)
        .assert()
        .code(if accepted { 0 } else { 5 });
}

#[test]
fn verify_agrees_with_pyhanko_on_our_outputs() {
    let Some(pki) = Pki::new() else { return };
    if !common::pyhanko_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let rsa = signed_by(&pki, dir.path(), "rsa", None);
    let ecdsa = signed_by(&pki, dir.path(), "ecdsa", Some("P-256"));
    for file in [&rsa, &ecdsa] {
        agrees_with_pyhanko(&pki, file, true);
    }

    // Co-signed: sign the output again with another key.
    let other = pki.leaf("second", None);
    let keystore = format!("pkcs12:{}", pki.p12(&other, PASSWORD, &[]).display());
    sealpdf()
        .arg("sign")
        .arg(&rsa)
        .args(["--keystore", &keystore, "--password-env", "SEALPDF_PW"])
        .env("SEALPDF_PW", PASSWORD)
        .assert()
        .success();
    agrees_with_pyhanko(&pki, &dir.path().join("rsa_signed_signed.pdf"), true);
}

#[test]
fn verify_agrees_with_pyhanko_on_a_tampered_copy() {
    let Some(pki) = Pki::new() else { return };
    if !common::pyhanko_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let file = tampered(dir.path(), &signed_by(&pki, dir.path(), "rsa", None));
    agrees_with_pyhanko(&pki, &file, false);
}

#[test]
fn verify_accepts_a_signature_made_by_pyhanko_then_ours() {
    let Some(pki) = Pki::new() else { return };
    if !common::pyhanko_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let third = pki.leaf("third-party", None);
    let p12 = pki.p12(&third, PASSWORD, &[]);
    let by_pyhanko = common::pyhanko_sign(
        pki.path(),
        &blank_pdf(1, false),
        &p12,
        PASSWORD,
        "ThirdParty",
    );
    let input = write(dir.path(), "chain.pdf", &by_pyhanko);

    let ours = pki.leaf("ours", None);
    let keystore = format!("pkcs12:{}", pki.p12(&ours, PASSWORD, &[]).display());
    sealpdf()
        .arg("sign")
        .arg(&input)
        .args(["--keystore", &keystore, "--password-env", "SEALPDF_PW"])
        .env("SEALPDF_PW", PASSWORD)
        .assert()
        .success();
    let chained = dir.path().join("chain_signed.pdf");

    sealpdf()
        .arg("ls")
        .arg(&chained)
        .assert()
        .success()
        .stdout(predicate::str::contains("third-party").and(predicate::str::contains("ours")));
    agrees_with_pyhanko(&pki, &chained, true);
}
