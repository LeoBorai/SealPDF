#![allow(dead_code)]

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread,
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

/// A request as the test server saw it.
#[derive(Debug, Clone)]
pub struct Received {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Received {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// What the test server answers.
pub enum Answer {
    Body(Vec<u8>),
    Status(u16),
}

pub struct Server {
    pub url: String,
    pub received: Arc<Mutex<Vec<Received>>>,
}

/// A local RFC 3161 TSA built on the OpenSSL CLI.
pub struct TestTsa {
    pub dir: tempfile::TempDir,
}

impl TestTsa {
    /// `None` when `openssl` is not installed.
    pub fn new() -> Option<Self> {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        // LibreSSL, which some systems ship as `openssl`, has no `ts` command.
        if !openssl(d, &["version"]) || !openssl(d, &["ts", "-help"]) {
            eprintln!("openssl with the `ts` command not found: skipping");
            return None;
        }
        std::fs::write(
            d.join("ext.cnf"),
            "extendedKeyUsage=critical,timeStamping\nkeyUsage=critical,digitalSignature\n",
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
                "/CN=Test TSA/O=sealpdf",
                "-days",
                "2",
                "-keyout",
                "tsa.key",
                "-out",
                "tsa.pem",
                "-addext",
                "extendedKeyUsage=critical,timeStamping"
            ]
        ));
        std::fs::write(d.join("tsa.serial"), "01\n").unwrap();
        std::fs::write(
            d.join("tsa.cnf"),
            "[tsa]\ndefault_tsa = tsa1\n[tsa1]\ndir = .\nserial = $dir/tsa.serial\ncrypto_device = builtin\n\
             signer_cert = $dir/tsa.pem\ncerts = $dir/tsa.pem\nsigner_key = $dir/tsa.key\nsigner_digest = sha256\n\
             default_policy = 1.2.3.4.1\nother_policies = 1.2.3.4.5, 1.2.3.4.6\n\
             digests = sha1, sha256, sha384, sha512\naccuracy = secs:1\nordering = yes\ntsa_name = yes\n\
             ess_cert_id_chain = no\ness_cert_id_alg = sha256\n",
        )
        .unwrap();
        Some(Self { dir })
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn cert_pem(&self) -> PathBuf {
        self.path().join("tsa.pem")
    }

    /// The TSA's `TimeStampResp` for a DER `TimeStampReq`.
    pub fn reply(&self, request_der: &[u8]) -> Vec<u8> {
        let d = self.path();
        std::fs::write(d.join("q.tsq"), request_der).unwrap();
        assert!(openssl(
            d,
            &[
                "ts",
                "-reply",
                "-queryfile",
                "q.tsq",
                "-config",
                "tsa.cnf",
                "-out",
                "r.tsr"
            ]
        ));
        std::fs::read(d.join("r.tsr")).unwrap()
    }

    /// `openssl ts -verify` of a bare token against the request it answered.
    pub fn verify_token(&self, request_der: &[u8], token_der: &[u8]) -> bool {
        let d = self.path();
        std::fs::write(d.join("v.tsq"), request_der).unwrap();
        std::fs::write(d.join("v.tst"), token_der).unwrap();
        openssl(
            d,
            &[
                "ts",
                "-verify",
                "-queryfile",
                "v.tsq",
                "-in",
                "v.tst",
                "-token_in",
                "-CAfile",
                "tsa.pem",
            ],
        )
    }

    /// `openssl ts -query` for a file's digest, as the reference encoding of a request.
    pub fn reference_query(&self, data: &[u8], hash: &str, cert: bool) -> Vec<u8> {
        let d = self.path();
        std::fs::write(d.join("data.bin"), data).unwrap();
        let mut args = vec![
            "ts",
            "-query",
            "-data",
            "data.bin",
            "-no_nonce",
            "-out",
            "ref.tsq",
        ];
        let flag = format!("-{hash}");
        args.push(&flag);
        if cert {
            args.push("-cert");
        }
        assert!(openssl(d, &args));
        std::fs::read(d.join("ref.tsq")).unwrap()
    }

    /// Serves HTTP on a free local port. `handler` decides each answer.
    pub fn serve<F>(&self, handler: F) -> Server
    where
        F: Fn(&Received) -> Answer + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/tsa", listener.local_addr().unwrap());
        let received = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&received);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let Some(req) = read_request(&mut stream) else {
                    continue;
                };
                let answer = handler(&req);
                log.lock().unwrap().push(req);
                let (status, body): (u16, Vec<u8>) = match answer {
                    Answer::Body(b) => (200, b),
                    Answer::Status(s) => (s, Vec::new()),
                };
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        Server { url, received }
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Received> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let headers: Vec<(String, String)> = head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[header_end..].to_vec();
    while body.len() < len {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some(Received { headers, body })
}
