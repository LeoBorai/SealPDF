//! Signs a dummy-signed PDF with the OpenSSL CLI and verifies the result with it again,
//! reading the covered bytes straight from `/ByteRange`. This checks the writer against
//! an implementation that shares no code with it. Skipped when `openssl` is not installed.
//!
//! Set `CERTSIGN_KEEP_DIR` to keep `signed.pdf` for inspection with other tools.

mod common;

use certsign_pdf::{IncrementalWriter, PdfDocument};
use common::*;
use lopdf::dictionary;
use std::{path::Path, process::Command};

fn openssl(args: &[&str], cwd: &Path) -> Option<bool> {
    Command::new("openssl")
        .args(args)
        .current_dir(cwd)
        .output()
        .ok()
        .map(|o| o.status.success())
}

/// Length in bytes of the DER element at the start of `data` (header included).
fn der_len(data: &[u8]) -> usize {
    assert_eq!(data[0], 0x30, "CMS starts with a SEQUENCE");
    if data[1] < 0x80 {
        return 2 + data[1] as usize;
    }
    let n = (data[1] & 0x7F) as usize;
    let len = data[2..2 + n]
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | *b as usize);
    2 + n + len
}

#[test]
fn openssl_signs_and_verifies_the_byte_range() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    if openssl(&["version"], d).is_none() {
        eprintln!("openssl not found: skipping");
        return;
    }
    assert_eq!(
        openssl(
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=certsign test",
                "-days",
                "1",
                "-keyout",
                "key.pem",
                "-out",
                "cert.pem"
            ],
            d
        ),
        Some(true)
    );

    for xref_stream in [false, true] {
        let (mut doc, ids) = base(1);
        let widget = add_sig_field(&mut doc, ids[0], "Sig1", [50, 50, 250, 120], None);
        let original = if xref_stream {
            save_modern(&mut doc)
        } else {
            save(&mut doc)
        };

        let pdf = PdfDocument::open(original.clone(), None).unwrap();
        let mut w = IncrementalWriter::new(&pdf).unwrap();
        let sig = w
            .add_signature(
                dictionary! { "Type" => "Sig", "Filter" => "Adobe.PPKLite", "SubFilter" => "adbe.pkcs7.detached" },
                8192,
            )
            .unwrap();
        w.modify(widget)
            .unwrap()
            .as_dict_mut()
            .unwrap()
            .set("V", sig);
        let prepared = w.finish_signature().unwrap();

        let signed: Vec<u8> = prepared.signed_parts().concat();
        std::fs::write(d.join("signed.bin"), &signed).unwrap();
        assert_eq!(
            openssl(
                &[
                    "cms",
                    "-sign",
                    "-binary",
                    "-in",
                    "signed.bin",
                    "-signer",
                    "cert.pem",
                    "-inkey",
                    "key.pem",
                    "-outform",
                    "DER",
                    "-out",
                    "sig.der",
                    "-md",
                    "sha256"
                ],
                d
            ),
            Some(true)
        );
        let cms = std::fs::read(d.join("sig.der")).unwrap();
        let out = prepared.embed(&cms).unwrap();

        // Recompute the covered bytes from the finished file, using only its /ByteRange text.
        let text = String::from_utf8_lossy(&out);
        let at = text.find("/ByteRange [").unwrap() + "/ByteRange [".len();
        let nums: Vec<usize> = text[at..text[at..].find(']').unwrap() + at]
            .split_whitespace()
            .map(|n| n.parse().unwrap())
            .collect();
        let covered = [
            &out[nums[0]..nums[0] + nums[1]],
            &out[nums[2]..nums[2] + nums[3]],
        ]
        .concat();
        assert_eq!(covered, signed, "stream={xref_stream}");

        // Pull the CMS back out of /Contents and trim the zero padding.
        let hex = std::str::from_utf8(&out[nums[1] + 1..nums[2] - 1]).unwrap();
        let raw: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let cms_back = &raw[..der_len(&raw)];
        assert_eq!(cms_back, &cms[..], "stream={xref_stream}");

        std::fs::write(d.join("covered.bin"), &covered).unwrap();
        std::fs::write(d.join("extracted.der"), cms_back).unwrap();
        assert_eq!(
            openssl(
                &[
                    "cms",
                    "-verify",
                    "-binary",
                    "-inform",
                    "DER",
                    "-in",
                    "extracted.der",
                    "-content",
                    "covered.bin",
                    "-noverify",
                    "-out",
                    "/dev/null"
                ],
                d
            ),
            Some(true),
            "openssl verifies the signature over the ByteRange (stream={xref_stream})"
        );

        // Flipping one covered byte must break it.
        let mut tampered = covered.clone();
        tampered[10] ^= 1;
        std::fs::write(d.join("tampered.bin"), &tampered).unwrap();
        assert_eq!(
            openssl(
                &[
                    "cms",
                    "-verify",
                    "-binary",
                    "-inform",
                    "DER",
                    "-in",
                    "extracted.der",
                    "-content",
                    "tampered.bin",
                    "-noverify",
                    "-out",
                    "/dev/null"
                ],
                d
            ),
            Some(false)
        );

        if let Ok(keep) = std::env::var("CERTSIGN_KEEP_DIR") {
            let name = if xref_stream {
                "signed-xrefstream.pdf"
            } else {
                "signed-classic.pdf"
            };
            std::fs::write(Path::new(&keep).join(name), &out).unwrap();
        }
    }
}
