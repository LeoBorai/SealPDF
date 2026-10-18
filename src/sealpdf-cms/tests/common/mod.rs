#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::Command,
};

/// Test PKI built with the OpenSSL CLI: a CA and RSA and EC leaves issued by it.
pub struct Pki {
    pub dir: tempfile::TempDir,
}

pub struct Leaf {
    pub key: PathBuf,
    pub cert_der: Vec<u8>,
}

fn openssl(dir: &Path, args: &[&str]) -> bool {
    Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .map(|o| {
            if !o.status.success() {
                eprintln!("openssl {args:?}: {}", String::from_utf8_lossy(&o.stderr));
            }
            o.status.success()
        })
        .unwrap_or(false)
}

impl Pki {
    /// `None` when `openssl` is not installed.
    pub fn new() -> Option<Self> {
        let dir = tempfile::tempdir().unwrap();
        if !openssl(dir.path(), &["version"]) {
            eprintln!("openssl not found: skipping");
            return None;
        }
        assert!(openssl(
            dir.path(),
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=Test CA/O=sealpdf",
                "-days",
                "2",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-addext",
                "basicConstraints=critical,CA:TRUE"
            ]
        ));
        std::fs::write(
            dir.path().join("leaf.cnf"),
            "certificatePolicies=1.3.6.1.4.1.99999.1\nkeyUsage=critical,digitalSignature,nonRepudiation\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("plain.cnf"),
            "keyUsage=critical,digitalSignature\n",
        )
        .unwrap();
        Some(Self { dir })
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// A leaf with a certificate policy (`with_policy`) or without one.
    pub fn leaf(&self, name: &str, ec: bool, with_policy: bool) -> Leaf {
        self.leaf_with(name, if ec { Some("P-256") } else { None }, with_policy)
    }

    /// An EC leaf on the given curve (`P-256`, `P-384`, `P-521`).
    pub fn ec_leaf(&self, name: &str, curve: &str) -> Leaf {
        self.leaf_with(name, Some(curve), false)
    }

    fn leaf_with(&self, name: &str, curve: Option<&str>, with_policy: bool) -> Leaf {
        let d = self.path();
        let (key, csr, pem, der) = (
            format!("{name}.key"),
            format!("{name}.csr"),
            format!("{name}.pem"),
            format!("{name}.der"),
        );
        let subj = format!("/CN={name}/O=sealpdf/serialNumber=IDCES-0001");
        let curve_opt = curve.map(|c| format!("ec_paramgen_curve:{c}"));
        let algo: Vec<&str> = match &curve_opt {
            Some(c) => vec!["-newkey", "ec", "-pkeyopt", c],
            None => vec!["-newkey", "rsa:2048"],
        };
        let mut args = vec![
            "req", "-new", "-nodes", "-keyout", &key, "-out", &csr, "-subj", &subj,
        ];
        args.extend_from_slice(&algo);
        assert!(openssl(d, &args));
        assert!(openssl(
            d,
            &[
                "x509",
                "-req",
                "-in",
                &csr,
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-days",
                "1",
                "-out",
                &pem,
                "-extfile",
                if with_policy { "leaf.cnf" } else { "plain.cnf" }
            ]
        ));
        assert!(openssl(
            d,
            &["x509", "-in", &pem, "-outform", "DER", "-out", &der]
        ));
        Leaf {
            key: d.join(key),
            cert_der: std::fs::read(d.join(der)).unwrap(),
        }
    }

    pub fn ca_der(&self) -> Vec<u8> {
        let d = self.path();
        assert!(openssl(
            d,
            &["x509", "-in", "ca.pem", "-outform", "DER", "-out", "ca.der"]
        ));
        std::fs::read(d.join("ca.der")).unwrap()
    }

    /// Signs `data` with `leaf.key` and `digest` (`sha256`, ...). RSA gives PKCS#1 v1.5,
    /// EC gives a DER `ECDSA-Sig-Value`.
    pub fn sign(&self, leaf: &Leaf, digest: &str, data: &[u8]) -> Vec<u8> {
        let d = self.path();
        std::fs::write(d.join("tosign.bin"), data).unwrap();
        assert!(openssl(
            d,
            &[
                "dgst",
                &format!("-{digest}"),
                "-sign",
                leaf.key.to_str().unwrap(),
                "-out",
                "sig.bin",
                "tosign.bin"
            ]
        ));
        std::fs::read(d.join("sig.bin")).unwrap()
    }

    /// Runs `openssl cms -verify` of a detached `cms` over `content`.
    pub fn verify(&self, cms: &[u8], content: &[u8]) -> bool {
        let d = self.path();
        std::fs::write(d.join("v.der"), cms).unwrap();
        std::fs::write(d.join("v.bin"), content).unwrap();
        openssl(
            d,
            &[
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-in",
                "v.der",
                "-content",
                "v.bin",
                "-noverify",
                "-out",
                "verified.out",
            ],
        )
    }

    /// Text dump of a CMS from `openssl cms -cmsout -print`.
    pub fn dump(&self, cms: &[u8]) -> String {
        let d = self.path();
        std::fs::write(d.join("dump.der"), cms).unwrap();
        let out = Command::new("openssl")
            .args([
                "cms", "-cmsout", "-print", "-inform", "DER", "-in", "dump.der",
            ])
            .current_dir(d)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}
