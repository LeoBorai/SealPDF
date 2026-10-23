#![doc = include_str!("../README.md")]

pub mod job;

use job::{inspect_json, offered, sign_file, signature_count};
use sealpdf_keystore::{Entry, KeyStore, KeychainKeyStore, Pkcs12KeyStore, StaticPrompt};
use std::{
    ffi::{CStr, CString, c_char, c_int, c_long, c_ulong},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};

/// The opaque handle the C side holds.
pub struct SealpdfCerts {
    store: Box<dyn KeyStore>,
    entries: Vec<Entry>,
}

const OK: c_int = 0;
const FAILED: c_int = 1;

fn to_c_string(text: &str) -> *mut c_char {
    // An interior NUL cannot be carried in a C string; drop it rather than lose the message.
    CString::new(text.replace('\0', ""))
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// # Safety
/// `error` is null or points to writable storage for a `char *`.
unsafe fn set_error(error: *mut *mut c_char, message: &str) {
    if !error.is_null() {
        unsafe { *error = to_c_string(message) };
    }
}

/// # Safety
/// `text` is null or a null-terminated string.
unsafe fn str_arg<'a>(text: *const c_char) -> Result<&'a str, String> {
    if text.is_null() {
        return Err("a required argument is missing".into());
    }
    unsafe { CStr::from_ptr(text) }
        .to_str()
        .map_err(|_| "an argument is not valid UTF-8".into())
}

/// Runs `f`, turning a panic into an error so it never unwinds into C.
fn guarded<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f))
        .unwrap_or_else(|_| Err("internal error: sealpdf panicked".into()))
}

/// Opens a store, lists what it offers and hands the result to C, or writes the error.
///
/// # Safety
/// `error` is null or points to writable storage for a `char *`.
unsafe fn open_certs(
    error: *mut *mut c_char,
    open: impl FnOnce() -> Result<Box<dyn KeyStore>, String>,
) -> *mut SealpdfCerts {
    let opened = guarded(|| {
        let store = open()?;
        let entries = offered(&*store)?;
        Ok(Box::new(SealpdfCerts { store, entries }))
    });
    match opened {
        Ok(certs) => Box::into_raw(certs),
        Err(message) => {
            unsafe { set_error(error, &message) };
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// `error` is null or points to writable storage for a `char *`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealpdf_certs_open(error: *mut *mut c_char) -> *mut SealpdfCerts {
    unsafe {
        open_certs(error, || {
            let store = KeychainKeyStore::open().map_err(|e| e.to_string())?;
            Ok(Box::new(store))
        })
    }
}

/// # Safety
/// `path` and `password` are null or null-terminated strings; `error` is null or points to
/// writable storage for a `char *`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealpdf_certs_open_pkcs12(
    path: *const c_char,
    password: *const c_char,
    error: *mut *mut c_char,
) -> *mut SealpdfCerts {
    unsafe {
        open_certs(error, || {
            let path = str_arg(path)?;
            // The prompt keeps the password as a `SecretString`, wiped when it is dropped.
            let prompt = StaticPrompt::new(str_arg(password)?);
            let store = Pkcs12KeyStore::open(path, &prompt).map_err(|e| e.to_string())?;
            Ok(Box::new(store))
        })
    }
}

/// # Safety
/// `certs` is null or a live handle from `sealpdf_certs_open`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealpdf_certs_count(certs: *const SealpdfCerts) -> c_ulong {
    unsafe { certs.as_ref() }.map_or(0, |c| c.entries.len() as c_ulong)
}

/// # Safety
/// `certs` is null or a live handle from `sealpdf_certs_open`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealpdf_certs_alias(
    certs: *const SealpdfCerts,
    index: c_ulong,
) -> *mut c_char {
    unsafe { certs.as_ref() }
        .and_then(|c| c.entries.get(usize::try_from(index).ok()?))
        .map_or(std::ptr::null_mut(), |e| to_c_string(&e.alias))
}

/// # Safety
/// `certs` is null or a live handle; the strings are null or null-terminated; `error` is null or
/// points to writable storage for a `char *`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealpdf_sign(
    certs: *const SealpdfCerts,
    input: *const c_char,
    output: *const c_char,
    alias: *const c_char,
    error: *mut *mut c_char,
) -> c_int {
    let result = guarded(|| {
        let certs = unsafe { certs.as_ref() }.ok_or("no certificate list")?;
        let (input, output, alias) =
            unsafe { (str_arg(input)?, str_arg(output)?, str_arg(alias)?) };
        sign_file(Path::new(input), Path::new(output), alias, &*certs.store)
    });
    match result {
        Ok(()) => OK,
        Err(message) => {
            unsafe { set_error(error, &message) };
            FAILED
        }
    }
}

/// # Safety
/// `path` is null or a null-terminated string; `error` is null or points to writable storage for
/// a `char *`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealpdf_signature_count(
    path: *const c_char,
    error: *mut *mut c_char,
) -> c_long {
    let result = guarded(|| signature_count(Path::new(unsafe { str_arg(path)? })));
    match result {
        Ok(count) => c_long::try_from(count).unwrap_or(c_long::MAX),
        Err(message) => {
            unsafe { set_error(error, &message) };
            -1
        }
    }
}

/// # Safety
/// `path` is null or a null-terminated string; `error` is null or points to writable storage for
/// a `char *`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealpdf_inspect(
    path: *const c_char,
    error: *mut *mut c_char,
) -> *mut c_char {
    let result = guarded(|| inspect_json(Path::new(unsafe { str_arg(path)? })));
    match result {
        Ok(json) => to_c_string(&json),
        Err(message) => {
            unsafe { set_error(error, &message) };
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// `certs` is null or a handle from `sealpdf_certs_open` not freed before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealpdf_certs_free(certs: *mut SealpdfCerts) {
    if !certs.is_null() {
        drop(unsafe { Box::from_raw(certs) });
    }
}

/// # Safety
/// `string` is null or a string returned by this library, not freed before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealpdf_string_free(string: *mut c_char) {
    if !string.is_null() {
        drop(unsafe { CString::from_raw(string) });
    }
}
