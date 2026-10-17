use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, Zeroizing};

/// Secret bytes derived from a password or PIN in the encoding a backend needs.
///
/// Backends often need a password in a form other than the `str` it came in, such as the
/// null-terminated UTF-16 big-endian string PKCS#12 derives its keys from. This holds that copy,
/// wipes it when dropped, and never prints it.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// The UTF-8 bytes of `secret`.
    pub fn utf8(secret: &SecretString) -> Self {
        Self(Zeroizing::new(secret.expose_secret().as_bytes().to_vec()))
    }

    /// `secret` as a PKCS#12 `BMPString`: UTF-16 big-endian, ending in a two-byte null.
    pub fn bmp_string(secret: &SecretString) -> Self {
        let text = secret.expose_secret();
        let mut bytes = Zeroizing::new(Vec::with_capacity(text.len() * 2 + 2));
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Overwrites the bytes now instead of at drop. The buffer is left empty.
    pub fn wipe(&mut self) {
        self.0.zeroize();
    }

    /// Capacity of the buffer, in bytes. Wiping clears all of it, not only the used part.
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    /// Bytes of the buffer's whole allocation, used and spare. Only for tests of [`Self::wipe`].
    #[doc(hidden)]
    pub fn raw_allocation(&mut self) -> &[u8] {
        let cap = self.0.capacity();
        let ptr = self.0.as_ptr();
        // SAFETY: `Zeroize for Vec<u8>` writes zeros over the whole capacity before clearing, so
        // every byte of the allocation is initialized once `wipe` ran; before it, the bytes past
        // `len` may be uninitialized, which callers of this test-only helper must not read.
        unsafe { std::slice::from_raw_parts(ptr, cap) }
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}
