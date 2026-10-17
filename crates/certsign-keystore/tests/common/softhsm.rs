//! A SoftHSM2 token set built once per test process.
//!
//! Needs the SoftHSM2 module and its `softhsm2-util`. They are found through `SOFTHSM2_MODULE` and
//! `SOFTHSM2_UTIL` or in the usual places. Without them the tests skip, unless
//! `CERTSIGN_REQUIRE_PKCS11=1` (set in CI) turns that into a failure.

use super::{Leaf, Pki, openssl};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    object::{Attribute, CertificateType, KeyType, ObjectClass},
    session::UserType,
    slot::Slot,
    types::AuthPin,
};
use p256::pkcs8::DecodePrivateKey as _;
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

pub const USER_PIN: &str = "1234";
const SO_PIN: &str = "12345678";

pub struct Fixture {
    pub module: PathBuf,
    pub pki: Pki,
    pub rsa: Leaf,
    pub ec256: Leaf,
    pub ec384: Leaf,
    /// Slot of the main token: three signing certificates and two CA certificates.
    pub main: u64,
    /// Three tokens with one signing certificate each, for tests that fail PINs.
    pub pin_tokens: [u64; 3],
    /// A token with no objects.
    pub empty: u64,
    /// A token whose EC private key is visible without login, next to a certificate with no key.
    pub visible: u64,
    pub visible_leaf: Leaf,
}

fn find_module() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SOFTHSM2_MODULE") {
        return Some(PathBuf::from(p));
    }
    [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

fn util(dir: &Path, module: &Path, args: &[&str]) -> Option<String> {
    let program = std::env::var("SOFTHSM2_UTIL").unwrap_or_else(|_| "softhsm2-util".into());
    let out = Command::new(program)
        .args(["--module", &module.display().to_string()])
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!(
            "softhsm2-util {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn init_token(dir: &Path, module: &Path, label: &str) -> u64 {
    let out = util(
        dir,
        module,
        &[
            "--init-token",
            "--free",
            "--label",
            label,
            "--so-pin",
            SO_PIN,
            "--pin",
            USER_PIN,
        ],
    )
    .expect("softhsm2-util --init-token");
    out.split("slot ")
        .last()
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no slot in: {out}"))
}

fn import_key(pki: &Pki, module: &Path, leaf: &Leaf, token: &str, id: &str) {
    let d = pki.path();
    let pem = format!("{}.pk8.pem", leaf.name);
    assert!(openssl(
        d,
        &[
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            &format!("{}.key", leaf.name),
            "-out",
            &pem
        ]
    ));
    assert!(
        util(
            d,
            module,
            &[
                "--import", &pem, "--token", token, "--label", &leaf.name, "--id", id, "--pin",
                USER_PIN
            ]
        )
        .is_some(),
        "importing the key of {}",
        leaf.name
    );
}

fn certificate(label: &str, id: u8, der: &[u8]) -> Vec<Attribute> {
    use der::{Decode, Encode};
    let parsed = x509_cert::Certificate::from_der(der).unwrap();
    let subject = parsed.tbs_certificate().subject().to_der().unwrap();
    let issuer = parsed.tbs_certificate().issuer().to_der().unwrap();
    vec![
        Attribute::Subject(subject),
        Attribute::Issuer(issuer),
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(CertificateType::X_509),
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(vec![id]),
        Attribute::Value(der.to_vec()),
    ]
}

/// The fixture, or `None` (after saying why) when SoftHSM2 is not available.
pub fn get() -> Option<&'static Fixture> {
    static FIXTURE: OnceLock<Option<Fixture>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let built = build();
            if built.is_none() && std::env::var("CERTSIGN_REQUIRE_PKCS11").as_deref() == Ok("1") {
                panic!("CERTSIGN_REQUIRE_PKCS11=1 but SoftHSM2 is not available");
            }
            built
        })
        .as_ref()
}

fn build() -> Option<Fixture> {
    let module = find_module().filter(|p| p.exists());
    let Some(module) = module else {
        eprintln!("no SoftHSM2 module (set SOFTHSM2_MODULE): skipping");
        return None;
    };
    let pki = Pki::new()?;
    let dir = pki.path().to_owned();
    let tokens = dir.join("tokens");
    std::fs::create_dir_all(&tokens).unwrap();
    std::fs::write(
        dir.join("softhsm2.conf"),
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens.display()
        ),
    )
    .unwrap();
    // SAFETY: set once, in the thread that builds the fixture, before the module is loaded and
    // before any other thread of this test process reads the variable.
    unsafe { std::env::set_var("SOFTHSM2_CONF", dir.join("softhsm2.conf")) };
    util(&dir, &module, &["--version"])?;

    let (rsa, ec256, ec384) = (
        pki.leaf("rsa", None),
        pki.leaf("ec256", Some("P-256")),
        pki.leaf("ec384", Some("P-384")),
    );
    let pin_leaves: Vec<Leaf> = (0..3)
        .map(|i| pki.leaf(&format!("pin-leaf-{i}"), None))
        .collect();
    let visible_leaf = pki.leaf("visible-ec", Some("P-256"));
    let unkeyed = pki.leaf("no-key", Some("P-256"));

    // Tokens and keys first, with the utility, while no module is loaded in this process.
    let main = init_token(&dir, &module, "certsign-main");
    let pin_tokens = [0, 1, 2].map(|i| init_token(&dir, &module, &format!("certsign-pin-{i}")));
    let empty = init_token(&dir, &module, "certsign-empty");
    let visible = init_token(&dir, &module, "certsign-visible");
    import_key(&pki, &module, &rsa, "certsign-main", "01");
    import_key(&pki, &module, &ec256, "certsign-main", "02");
    import_key(&pki, &module, &ec384, "certsign-main", "03");
    for (i, leaf) in pin_leaves.iter().enumerate() {
        import_key(&pki, &module, leaf, &format!("certsign-pin-{i}"), "01");
    }

    // Then certificates, and the visible key, through the module. It is finalized afterwards so
    // that the module the tests load sees everything on disk.
    let ctx = Pkcs11::new(&module).ok()?;
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .ok()?;
    let put = |slot: u64, objects: Vec<Vec<Attribute>>| {
        let slot = Slot::try_from(slot).unwrap();
        let session = ctx.open_rw_session(slot).unwrap();
        session
            .login(UserType::User, Some(&AuthPin::from(USER_PIN.to_owned())))
            .unwrap();
        for template in objects {
            session.create_object(&template).unwrap();
        }
        session.logout().unwrap();
    };
    put(
        main,
        vec![
            certificate("rsa", 1, &rsa.cert_der),
            certificate("ec256", 2, &ec256.cert_der),
            certificate("ec384", 3, &ec384.cert_der),
            certificate("intermediate", 10, &pki.intermediate_der()),
            certificate("root", 11, &pki.root_der()),
        ],
    );
    for (i, leaf) in pin_leaves.iter().enumerate() {
        put(
            pin_tokens[i],
            vec![certificate("pin-leaf", 1, &leaf.cert_der)],
        );
    }
    let scalar = p256::SecretKey::from_pkcs8_der(&pki.pkcs8(&visible_leaf))
        .unwrap()
        .to_bytes()
        .to_vec();
    put(
        visible,
        vec![
            certificate("visible-ec", 5, &visible_leaf.cert_der),
            certificate("no-key", 6, &unkeyed.cert_der),
            vec![
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(KeyType::EC),
                Attribute::Token(true),
                Attribute::Private(false),
                Attribute::Sensitive(false),
                Attribute::Sign(true),
                Attribute::Id(vec![5]),
                Attribute::Label(b"visible-ec".to_vec()),
                Attribute::EcParams(vec![
                    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
                ]),
                Attribute::Value(scalar),
            ],
        ],
    );
    ctx.finalize().ok()?;

    Some(Fixture {
        module,
        pki,
        rsa,
        ec256,
        ec384,
        main,
        pin_tokens,
        empty,
        visible,
        visible_leaf,
    })
}
