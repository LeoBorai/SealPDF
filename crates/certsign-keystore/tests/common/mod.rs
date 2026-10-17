#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::Command,
};

pub fn openssl(dir: &Path, args: &[&str]) -> bool {
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

/// A root, an intermediate and leaves issued by the intermediate, built with the OpenSSL CLI.
pub struct Pki {
    pub dir: tempfile::TempDir,
}

pub struct Leaf {
    pub name: String,
    pub cert_der: Vec<u8>,
}

impl Pki {
    /// `None` when `openssl` is not installed.
    pub fn new() -> Option<Self> {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        if !openssl(d, &["version"]) {
            eprintln!("openssl not found: skipping");
            return None;
        }
        std::fs::write(
            d.join("ca.cnf"),
            "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n",
        )
        .unwrap();
        std::fs::write(
            d.join("leaf.cnf"),
            "keyUsage=critical,digitalSignature,nonRepudiation\n",
        )
        .unwrap();
        assert!(openssl(
            d,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=Root CA",
                "-days",
                "3",
                "-keyout",
                "root.key",
                "-out",
                "root.pem",
                "-addext",
                "basicConstraints=critical,CA:TRUE"
            ]
        ));
        assert!(openssl(
            d,
            &[
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=Intermediate CA",
                "-keyout",
                "int.key",
                "-out",
                "int.csr"
            ]
        ));
        assert!(openssl(
            d,
            &[
                "x509",
                "-req",
                "-in",
                "int.csr",
                "-CA",
                "root.pem",
                "-CAkey",
                "root.key",
                "-CAcreateserial",
                "-days",
                "2",
                "-out",
                "int.pem",
                "-extfile",
                "ca.cnf"
            ]
        ));
        // Intermediate first, then root: the order a file might store them in.
        let chain = [
            std::fs::read(d.join("int.pem")).unwrap(),
            std::fs::read(d.join("root.pem")).unwrap(),
        ]
        .concat();
        std::fs::write(d.join("chain.pem"), chain).unwrap();
        Some(Self { dir })
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn der(&self, pem: &str) -> Vec<u8> {
        let out = format!("{pem}.conv.der");
        assert!(openssl(
            self.path(),
            &["x509", "-in", pem, "-outform", "DER", "-out", &out]
        ));
        std::fs::read(self.path().join(out)).unwrap()
    }

    pub fn root_der(&self) -> Vec<u8> {
        self.der("root.pem")
    }

    pub fn intermediate_der(&self) -> Vec<u8> {
        self.der("int.pem")
    }

    /// `curve` is `None` for RSA, or `P-256`, `P-384`, `P-521`.
    pub fn leaf(&self, name: &str, curve: Option<&str>) -> Leaf {
        let d = self.path();
        let (key, csr, pem) = (
            format!("{name}.key"),
            format!("{name}.csr"),
            format!("{name}.pem"),
        );
        let subj = format!("/CN={name}/O=certsign");
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
                "int.pem",
                "-CAkey",
                "int.key",
                "-CAcreateserial",
                "-days",
                "1",
                "-out",
                &pem,
                "-extfile",
                "leaf.cnf"
            ]
        ));
        Leaf {
            name: name.to_owned(),
            cert_der: self.der(&pem),
        }
    }

    /// Exports `name`'s key and chain as `<name>.p12`.
    pub fn p12(&self, leaf: &Leaf, password: &str, extra: &[&str]) -> PathBuf {
        let d = self.path();
        let out = format!("{}.p12", leaf.name);
        let (key, pem) = (format!("{}.key", leaf.name), format!("{}.pem", leaf.name));
        let pass = format!("pass:{password}");
        let mut args = vec![
            "pkcs12",
            "-export",
            "-inkey",
            &key,
            "-in",
            &pem,
            "-certfile",
            "chain.pem",
            "-name",
            &leaf.name,
            "-passout",
            &pass,
            "-out",
            &out,
        ];
        args.extend_from_slice(extra);
        assert!(openssl(d, &args));
        d.join(out)
    }

    /// The key as unencrypted PKCS#8 DER.
    pub fn pkcs8(&self, leaf: &Leaf) -> Vec<u8> {
        let d = self.path();
        let out = format!("{}.pk8", leaf.name);
        assert!(openssl(
            d,
            &[
                "pkcs8",
                "-topk8",
                "-nocrypt",
                "-in",
                &format!("{}.key", leaf.name),
                "-outform",
                "DER",
                "-out",
                &out
            ]
        ));
        std::fs::read(d.join(out)).unwrap()
    }

    /// Checks `signature` over `data` with the public key of `leaf`, using OpenSSL.
    pub fn verify(&self, leaf: &Leaf, digest: &str, data: &[u8], signature: &[u8]) -> bool {
        let d = self.path();
        std::fs::write(d.join("vdata.bin"), data).unwrap();
        std::fs::write(d.join("vsig.bin"), signature).unwrap();
        let pubkey = format!("{}.pub", leaf.name);
        assert!(openssl(
            d,
            &[
                "x509",
                "-in",
                &format!("{}.pem", leaf.name),
                "-pubkey",
                "-noout",
                "-out",
                &pubkey
            ]
        ));
        openssl(
            d,
            &[
                "dgst",
                &format!("-{digest}"),
                "-verify",
                &pubkey,
                "-signature",
                "vsig.bin",
                "vdata.bin",
            ],
        )
    }
}
