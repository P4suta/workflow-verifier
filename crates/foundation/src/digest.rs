use crate::SHA256_HEX_DIGITS;
use sha2::{Digest, Sha256};
use std::fmt;

const HEX: &[u8; 16] = b"0123456789abcdef";
const DIGEST_WRITE_BUFFER_BYTES: usize = 8 * 1024;

fn lowercase_hex(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len().saturating_mul(2));
    for byte in input {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Lowercase SHA-256 hexadecimal without a scheme prefix.
#[must_use]
pub fn sha256_hex(input: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(input.as_ref());
    debug_assert_eq!(digest.len().saturating_mul(2), SHA256_HEX_DIGITS);
    lowercase_hex(&digest)
}

/// Canonical content identity used by every public protocol.
#[must_use]
pub fn content_digest(input: impl AsRef<[u8]>) -> String {
    format!("sha256:{}", sha256_hex(input))
}

pub(crate) struct ContentDigestWriter {
    hasher: Sha256,
    buffer: Vec<u8>,
}

impl Default for ContentDigestWriter {
    fn default() -> Self {
        Self {
            hasher: Sha256::new(),
            buffer: Vec::with_capacity(DIGEST_WRITE_BUFFER_BYTES),
        }
    }
}

impl fmt::Write for ContentDigestWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let bytes = value.as_bytes();
        if bytes.len() >= DIGEST_WRITE_BUFFER_BYTES {
            self.flush();
            self.hasher.update(bytes);
        } else {
            if self.buffer.len().saturating_add(bytes.len()) > DIGEST_WRITE_BUFFER_BYTES {
                self.flush();
            }
            self.buffer.extend_from_slice(bytes);
        }
        Ok(())
    }
}

impl ContentDigestWriter {
    fn flush(&mut self) {
        if !self.buffer.is_empty() {
            self.hasher.update(&self.buffer);
            self.buffer.clear();
        }
    }

    pub(crate) fn finish(mut self) -> String {
        self.flush();
        format!("sha256:{}", lowercase_hex(&self.hasher.finalize()))
    }
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
