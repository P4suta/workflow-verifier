use crate::SHA256_HEX_DIGITS;
use sha2::{Digest, Sha256};

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase SHA-256 hexadecimal without a scheme prefix.
#[must_use]
pub fn sha256_hex(input: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(input.as_ref());
    let mut output = String::with_capacity(SHA256_HEX_DIGITS);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Canonical content identity used by every public protocol.
#[must_use]
pub fn content_digest(input: impl AsRef<[u8]>) -> String {
    format!("sha256:{}", sha256_hex(input))
}

#[cfg(test)]
mod tests {
    use super::{content_digest, sha256_hex};

    #[test]
    fn standard_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            content_digest(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
