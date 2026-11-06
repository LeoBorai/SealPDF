#![allow(dead_code)]

/// A self-signed certificate in a `.p12`, made with the OpenSSL CLI. `None` without OpenSSL.
pub fn make_p12(dir: &std::path::Path, password: &str) -> Option<std::path::PathBuf> {
    let run = |args: &[&str]| {
        std::process::Command::new("openssl")
            .args(args)
            .current_dir(dir)
            .output()
            .is_ok_and(|o| o.status.success())
    };
    let pass = format!("pass:{password}");
    let made = run(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "k.pem",
        "-out",
        "c.pem",
        "-subj",
        "/CN=Ada Lovelace",
        "-days",
        "2",
    ]) && run(&[
        "pkcs12", "-export", "-inkey", "k.pem", "-in", "c.pem", "-name", "Ada", "-passout", &pass,
        "-out", "ada.p12",
    ]);
    if !made {
        eprintln!("openssl not found: skipping");
        return None;
    }
    Some(dir.join("ada.p12"))
}

/// A PDF of `pages` pages of 595 x 842 points.
pub fn blank_pdf(pages: usize) -> Vec<u8> {
    use lopdf::{Document, Object, dictionary};
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
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}
