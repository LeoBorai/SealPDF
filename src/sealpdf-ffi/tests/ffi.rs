use sealpdf_ffi::*;
use std::ffi::{CStr, c_char};

/// Reads and releases an error string the library wrote.
fn take(error: *mut c_char) -> String {
    assert!(!error.is_null(), "no error message was written");
    let message = unsafe { CStr::from_ptr(error) }
        .to_string_lossy()
        .into_owned();
    unsafe { sealpdf_string_free(error) };
    message
}

#[test]
fn a_missing_handle_is_an_error_not_a_crash() {
    let mut error = std::ptr::null_mut();
    let code = unsafe {
        sealpdf_sign(
            std::ptr::null(),
            c"a.pdf".as_ptr(),
            c"b.pdf".as_ptr(),
            c"x".as_ptr(),
            &mut error,
        )
    };
    assert_eq!(code, 1);
    assert!(take(error).contains("no certificate list"));
}

#[test]
fn null_handles_and_strings_are_ignored() {
    unsafe {
        assert_eq!(sealpdf_certs_count(std::ptr::null()), 0);
        assert!(sealpdf_certs_alias(std::ptr::null(), 0).is_null());
        sealpdf_certs_free(std::ptr::null_mut());
        sealpdf_string_free(std::ptr::null_mut());
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn the_keychain_is_macos_only() {
    let mut error = std::ptr::null_mut();
    let certs = unsafe { sealpdf_certs_open(&mut error) };
    assert!(certs.is_null());
    assert!(take(error).contains("macOS"));
    // The error argument is optional.
    assert!(unsafe { sealpdf_certs_open(std::ptr::null_mut()) }.is_null());
}

#[test]
fn a_pkcs12_file_that_is_missing_is_an_error() {
    let mut error = std::ptr::null_mut();
    let certs = unsafe {
        sealpdf_certs_open_pkcs12(c"/nonexistent/x.p12".as_ptr(), c"pw".as_ptr(), &mut error)
    };
    assert!(certs.is_null());
    assert!(take(error).contains("cannot read"));

    let mut error = std::ptr::null_mut();
    let certs = unsafe { sealpdf_certs_open_pkcs12(std::ptr::null(), c"pw".as_ptr(), &mut error) };
    assert!(certs.is_null());
    take(error);
}

/// A self-signed certificate in a `.p12`, made with the OpenSSL CLI. `None` without OpenSSL.
fn make_p12(dir: &std::path::Path, password: &str) -> Option<std::path::PathBuf> {
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

fn blank_pdf() -> Vec<u8> {
    use lopdf::{Document, Object, dictionary};
    let mut doc = Document::with_version("1.5");
    let tree = doc.new_object_id();
    let page = doc.add_object(dictionary! { "Type" => "Page", "Parent" => tree });
    doc.objects.insert(
        tree,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![Object::Reference(page)], "Count" => 1,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        }),
    );
    let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => tree });
    doc.trailer.set("Root", catalog);
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}

#[test]
fn signs_a_pdf_with_a_certificate_file() {
    let dir = tempfile::tempdir().unwrap();
    let Some(p12) = make_p12(dir.path(), "hunter2") else {
        return;
    };
    let path = std::ffi::CString::new(p12.to_str().unwrap()).unwrap();

    // A wrong password opens nothing and says so.
    let mut error = std::ptr::null_mut();
    let certs = unsafe { sealpdf_certs_open_pkcs12(path.as_ptr(), c"wrong".as_ptr(), &mut error) };
    assert!(certs.is_null());
    assert!(take(error).to_lowercase().contains("password"));

    let mut error = std::ptr::null_mut();
    let certs =
        unsafe { sealpdf_certs_open_pkcs12(path.as_ptr(), c"hunter2".as_ptr(), &mut error) };
    assert!(!certs.is_null(), "{}", take(error));
    assert_eq!(unsafe { sealpdf_certs_count(certs) }, 1);
    let alias = unsafe { sealpdf_certs_alias(certs, 0) };
    let alias_text = unsafe { CStr::from_ptr(alias) }
        .to_str()
        .unwrap()
        .to_owned();

    let input = dir.path().join("in.pdf");
    let output = dir.path().join("out.pdf");
    std::fs::write(&input, blank_pdf()).unwrap();
    let (input_c, output_c) = (
        std::ffi::CString::new(input.to_str().unwrap()).unwrap(),
        std::ffi::CString::new(output.to_str().unwrap()).unwrap(),
    );
    let mut error = std::ptr::null_mut();
    let code = unsafe {
        sealpdf_sign(
            certs,
            input_c.as_ptr(),
            output_c.as_ptr(),
            alias,
            &mut error,
        )
    };
    if code != 0 {
        panic!("{}", take(error));
    }

    let signed = std::fs::read(&output).unwrap();
    let pdf = sealpdf_pdf::PdfDocument::open(signed, None).unwrap();
    assert_eq!(pdf.signatures().len(), 1);
    assert!(!alias_text.is_empty());

    unsafe {
        sealpdf_string_free(alias);
        sealpdf_certs_free(certs);
    }
}

/// Signs a blank PDF through the C interface and returns the signed file. `None` without OpenSSL.
fn signed_through_ffi(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let p12 = make_p12(dir, "hunter2")?;
    let path = std::ffi::CString::new(p12.to_str().unwrap()).unwrap();
    let mut error = std::ptr::null_mut();
    let certs =
        unsafe { sealpdf_certs_open_pkcs12(path.as_ptr(), c"hunter2".as_ptr(), &mut error) };
    assert!(!certs.is_null(), "{}", take(error));
    let alias = unsafe { sealpdf_certs_alias(certs, 0) };

    let (input, output) = (dir.join("in.pdf"), dir.join("out.pdf"));
    std::fs::write(&input, blank_pdf()).unwrap();
    let (input_c, output_c) = (
        std::ffi::CString::new(input.to_str().unwrap()).unwrap(),
        std::ffi::CString::new(output.to_str().unwrap()).unwrap(),
    );
    let mut error = std::ptr::null_mut();
    let code = unsafe {
        sealpdf_sign(
            certs,
            input_c.as_ptr(),
            output_c.as_ptr(),
            alias,
            &mut error,
        )
    };
    assert_eq!(
        code,
        0,
        "{}",
        if code == 0 {
            String::new()
        } else {
            take(error)
        }
    );
    unsafe {
        sealpdf_string_free(alias);
        sealpdf_certs_free(certs);
    }
    Some(output)
}

fn c_path(path: &std::path::Path) -> std::ffi::CString {
    std::ffi::CString::new(path.to_str().unwrap()).unwrap()
}

#[test]
fn counts_the_signatures_of_a_pdf() {
    let dir = tempfile::tempdir().unwrap();
    let Some(signed) = signed_through_ffi(dir.path()) else {
        return;
    };
    let plain = dir.path().join("plain.pdf");
    std::fs::write(&plain, blank_pdf()).unwrap();

    let mut error = std::ptr::null_mut();
    assert_eq!(
        unsafe { sealpdf_signature_count(c_path(&signed).as_ptr(), &mut error) },
        1
    );
    assert_eq!(
        unsafe { sealpdf_signature_count(c_path(&plain).as_ptr(), &mut error) },
        0
    );
    assert!(error.is_null(), "no message is written on success");
}

#[test]
fn inspects_a_pdf_and_returns_the_report_as_json() {
    let dir = tempfile::tempdir().unwrap();
    let Some(signed) = signed_through_ffi(dir.path()) else {
        return;
    };

    let mut error = std::ptr::null_mut();
    let json = unsafe { sealpdf_inspect(c_path(&signed).as_ptr(), &mut error) };
    assert!(!json.is_null(), "{}", take(error));
    let text = unsafe { CStr::from_ptr(json) }.to_str().unwrap().to_owned();
    unsafe { sealpdf_string_free(json) };

    // The same text the command line prints with `--json`.
    let pdf = sealpdf_pdf::PdfDocument::open(std::fs::read(&signed).unwrap(), None).unwrap();
    let report = sealpdf_validate::inspect(&pdf, &sealpdf_core::SystemClock).unwrap();
    assert_eq!(text, report.to_json());

    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["signatures"][0]["signer"], "Ada Lovelace");
    assert_eq!(value["verdicts"][0]["verdict"], "OK");
}

#[test]
fn a_file_that_is_not_a_pdf_is_an_error_for_both_calls() {
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("notes.pdf");
    std::fs::write(&junk, b"just some text").unwrap();
    let path = c_path(&junk);

    let mut error = std::ptr::null_mut();
    assert_eq!(
        unsafe { sealpdf_signature_count(path.as_ptr(), &mut error) },
        -1
    );
    assert!(take(error).contains("invalid PDF"));

    let mut error = std::ptr::null_mut();
    assert!(unsafe { sealpdf_inspect(path.as_ptr(), &mut error) }.is_null());
    assert!(take(error).contains("invalid PDF"));
}

#[test]
fn missing_files_and_arguments_are_errors_not_crashes() {
    let mut error = std::ptr::null_mut();
    assert_eq!(
        unsafe { sealpdf_signature_count(c"/nonexistent/x.pdf".as_ptr(), &mut error) },
        -1
    );
    assert!(take(error).contains("cannot read"));

    let mut error = std::ptr::null_mut();
    assert!(unsafe { sealpdf_inspect(std::ptr::null(), &mut error) }.is_null());
    take(error);

    // The error argument is optional.
    assert_eq!(
        unsafe { sealpdf_signature_count(std::ptr::null(), std::ptr::null_mut()) },
        -1
    );
    assert!(
        unsafe { sealpdf_inspect(c"/nonexistent/x.pdf".as_ptr(), std::ptr::null_mut()) }.is_null()
    );
}
