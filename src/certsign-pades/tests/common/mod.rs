#![allow(dead_code)]
// Fixtures shared by the tests: a PKI built with the OpenSSL CLI, PDFs, and pyHanko as a reference.

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
        // The subject comes from a config file: on Windows a non-ASCII command-line argument
        // does not reach OpenSSL as UTF-8.
        let conf = format!("{name}.req.cnf");
        std::fs::write(
            d.join(&conf),
            format!(
                "[req]\ndistinguished_name = dn\nprompt = no\nutf8 = yes\nstring_mask = utf8only\n\n[dn]\nCN = {name}\nO = certsign\n"
            ),
        )
        .unwrap();
        let curve_opt = curve.map(|c| format!("ec_paramgen_curve:{c}"));
        let algo: Vec<&str> = match &curve_opt {
            Some(c) => vec!["-newkey", "ec", "-pkeyopt", c],
            None => vec!["-newkey", "rsa:2048"],
        };
        let mut args = vec![
            "req", "-utf8", "-new", "-nodes", "-config", &conf, "-keyout", &key, "-out", &csr,
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
        // Unique file names: tests of one process may verify at the same time.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = self.path();
        let (data_file, sig_file, pubkey) = (
            format!("vdata{n}.bin"),
            format!("vsig{n}.bin"),
            format!("{}.{n}.pub", leaf.name),
        );
        std::fs::write(d.join(&data_file), data).unwrap();
        std::fs::write(d.join(&sig_file), signature).unwrap();
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
                &sig_file,
                &data_file,
            ],
        )
    }
}

use lopdf::{Document, Object, StringFormat, dictionary};

/// A PDF with `pages` empty pages, 595 x 842 points.
pub fn blank_pdf(pages: usize, modern: bool) -> Vec<u8> {
    let mut doc = Document::with_version("1.5");
    let tree = doc.new_object_id();
    let kids: Vec<Object> = (0..pages)
        .map(|_| {
            Object::Reference(doc.add_object(dictionary! { "Type" => "Page", "Parent" => tree }))
        })
        .collect();
    doc.objects.insert(
        tree,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => kids, "Count" => pages as i64,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        }),
    );
    let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => tree });
    doc.trailer.set("Root", catalog);
    let id = Object::String(b"certsign-test-id!".to_vec(), StringFormat::Hexadecimal);
    doc.trailer.set("ID", vec![id.clone(), id]);
    doc.reference_table.cross_reference_type = if modern {
        lopdf::xref::XrefType::CrossReferenceStream
    } else {
        lopdf::xref::XrefType::CrossReferenceTable
    };
    let mut out = Vec::new();
    if modern {
        doc.save_modern(&mut out).unwrap();
    } else {
        doc.save_to(&mut out).unwrap();
    }
    out
}

/// A PDF certified with DocMDP at `level` (1, 2 or 3).
pub fn certified_pdf(level: i64) -> Vec<u8> {
    let mut doc = Document::load_mem(&blank_pdf(1, false)).unwrap();
    let catalog = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
    let params =
        doc.add_object(dictionary! { "Type" => "TransformParams", "P" => level, "V" => "1.2" });
    let sig = doc.add_object(dictionary! {
        "Type" => "Sig", "Filter" => "Adobe.PPKLite", "SubFilter" => "adbe.pkcs7.detached",
        "ByteRange" => vec![0.into(), 1.into(), 2.into(), 3.into()],
        "Contents" => Object::String(vec![0; 8], StringFormat::Hexadecimal),
        "Reference" => vec![Object::Dictionary(dictionary! {
            "Type" => "SigRef", "TransformMethod" => "DocMDP", "TransformParams" => params,
        })],
    });
    let perms = doc.add_object(dictionary! { "DocMDP" => sig });
    doc.get_object_mut(catalog)
        .unwrap()
        .as_dict_mut()
        .unwrap()
        .set("Perms", perms);
    let mut out = Vec::new();
    doc.reference_table.cross_reference_type = lopdf::xref::XrefType::CrossReferenceTable;
    doc.save_to(&mut out).unwrap();
    out
}

/// What pyHanko says about the signatures of a PDF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyhankoSignature {
    pub field: String,
    pub intact: bool,
    pub valid: bool,
    pub entire_file: bool,
}

fn python() -> String {
    std::env::var("CERTSIGN_PYTHON").unwrap_or_else(|_| "python3".into())
}

/// Whether pyHanko is importable. Missing pyHanko skips tests, unless `CERTSIGN_REQUIRE_PYHANKO=1`.
pub fn pyhanko_available() -> bool {
    let ok = Command::new(python())
        .args(["-c", "import pyhanko"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok && std::env::var("CERTSIGN_REQUIRE_PYHANKO").as_deref() == Ok("1") {
        panic!("CERTSIGN_REQUIRE_PYHANKO=1 but pyHanko is not importable");
    }
    if !ok {
        eprintln!("pyHanko not available: skipping");
    }
    ok
}

fn script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(name)
}

/// Validates every signature in `pdf` with pyHanko.
pub fn pyhanko_validate(dir: &Path, pdf: &[u8]) -> Vec<PyhankoSignature> {
    let file = dir.join("check.pdf");
    std::fs::write(&file, pdf).unwrap();
    let out = Command::new(python())
        .arg(script("pyhanko_check.py"))
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() == 5 && f[0] == "SIG").then(|| PyhankoSignature {
                field: f[1].to_owned(),
                intact: f[2] == "True",
                valid: f[3] == "True",
                entire_file: f[4] == "True",
            })
        })
        .collect()
}

/// Signs `pdf` with pyHanko, as a third party would.
pub fn pyhanko_sign(dir: &Path, pdf: &[u8], p12: &Path, password: &str, field: &str) -> Vec<u8> {
    let input = dir.join("tp-in.pdf");
    let output = dir.join("tp-out.pdf");
    std::fs::write(&input, pdf).unwrap();
    let out = Command::new(python())
        .arg(script("pyhanko_sign.py"))
        .args([
            &input,
            &PathBuf::from(p12),
            &PathBuf::from(password),
            &output,
            &PathBuf::from(field),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(output).unwrap()
}
