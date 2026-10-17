use certsign_keystore::{ExposeSecret, SecretBytes, SecretString};

#[test]
fn bmp_string_is_utf16_big_endian_with_a_null_terminator() {
    let s = SecretString::from("pä€".to_owned());
    let bytes = SecretBytes::bmp_string(&s);
    assert_eq!(
        bytes.expose(),
        [0x00, 0x70, 0x00, 0xE4, 0x20, 0xAC, 0x00, 0x00]
    );
    // Characters outside the BMP become surrogate pairs.
    let emoji = SecretString::from("😀".to_owned());
    assert_eq!(
        SecretBytes::bmp_string(&emoji).expose(),
        [0xD8, 0x3D, 0xDE, 0x00, 0x00, 0x00]
    );
    // The empty password is just the terminator, as PKCS#12 defines it.
    assert_eq!(
        SecretBytes::bmp_string(&SecretString::from(String::new())).expose(),
        [0, 0]
    );
}

#[test]
fn utf8_bytes() {
    let s = SecretString::from("clave-ñ".to_owned());
    assert_eq!(SecretBytes::utf8(&s).expose(), "clave-ñ".as_bytes());
}

#[test]
fn wipe_overwrites_the_whole_allocation() {
    let secret = SecretString::from("a-very-secret-password-1234".to_owned());
    let mut bytes = SecretBytes::bmp_string(&secret);
    let capacity = bytes.capacity();
    assert!(capacity >= bytes.expose().len());
    assert!(
        bytes.expose().iter().any(|b| *b != 0),
        "there is something to wipe"
    );

    bytes.wipe();

    assert!(bytes.expose().is_empty(), "no bytes are left to read");
    assert!(
        bytes.raw_allocation().iter().all(|b| *b == 0),
        "every byte of the allocation was overwritten, including the spare capacity"
    );
    assert_eq!(
        bytes.capacity(),
        capacity,
        "same allocation, wiped in place"
    );
}

#[test]
fn nothing_prints_the_secret() {
    let s = SecretString::from("hunter2".to_owned());
    let bytes = SecretBytes::utf8(&s);
    for text in [format!("{s:?}"), format!("{bytes:?}")] {
        assert!(!text.contains("hunter2"), "{text}");
    }
    // Reading it back takes an explicit call.
    assert_eq!(s.expose_secret(), "hunter2");
}
