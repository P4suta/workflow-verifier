use crate::foundation::SHA256_HEX_DIGITS;
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

/// A SHA-256 value in its native binary representation.
///
/// Digests stay binary inside the analyzer and are rendered as lowercase hex
/// only at a protocol boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    /// Hash one uninterpreted byte string.
    #[must_use]
    pub fn of_bytes(input: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(input.as_ref()).into())
    }

    /// Start a domain-separated composite digest.
    #[must_use]
    pub fn builder(domain: &'static [u8]) -> DigestBuilder {
        DigestBuilder::new(domain)
    }

    /// Access the authenticated bytes without allocating a hexadecimal string.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hexadecimal without a scheme prefix.
    #[must_use]
    pub fn hex(self) -> String {
        lowercase_hex(&self.0)
    }

    /// Parse the canonical `sha256:<lowercase-hex>` boundary representation.
    ///
    /// # Errors
    /// Rejects the wrong prefix, width, uppercase, or non-hexadecimal bytes.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err("digest must start with sha256:");
        };
        if hex.len() != SHA256_HEX_DIGITS {
            return Err("digest must contain exactly 64 hexadecimal digits");
        }
        let mut bytes = [0u8; 32];
        let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
        debug_assert!(remainder.is_empty());
        for (index, pair) in pairs.iter().enumerate() {
            let nibble = |value: u8| match value {
                b'0'..=b'9' => Some(value - b'0'),
                b'a'..=b'f' => Some(value - b'a' + 10),
                _ => None,
            };
            let Some(high) = nibble(pair[0]) else {
                return Err("digest must use lowercase hexadecimal");
            };
            let Some(low) = nibble(pair[1]) else {
                return Err("digest must use lowercase hexadecimal");
            };
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sha256:")?;
        formatter.write_str(&lowercase_hex(&self.0))
    }
}

/// Incremental, unambiguous hashing for structured analyzer identities.
///
/// Every component is prefixed by its big-endian byte length. The first
/// component is a mandatory domain tag, preventing cross-protocol reuse.
#[derive(Clone, Debug)]
pub struct DigestBuilder {
    hasher: Sha256,
}

impl DigestBuilder {
    #[must_use]
    pub fn new(domain: &'static [u8]) -> Self {
        let mut output = Self {
            hasher: Sha256::new(),
        };
        output.add(domain);
        output
    }

    /// Add one length-delimited field.
    pub fn add(&mut self, value: impl AsRef<[u8]>) -> &mut Self {
        let value = value.as_ref();
        let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
        self.hasher.update(length.to_be_bytes());
        self.hasher.update(value);
        self
    }

    /// Finish without allocating an intermediate hexadecimal string.
    #[must_use]
    pub fn finish(self) -> ContentDigest {
        ContentDigest(self.hasher.finalize().into())
    }
}

/// Lowercase SHA-256 hexadecimal without a scheme prefix.
#[must_use]
pub fn sha256_hex(input: impl AsRef<[u8]>) -> String {
    ContentDigest::of_bytes(input).hex()
}

/// Canonical content identity used by every public protocol.
#[must_use]
pub fn content_digest(input: impl AsRef<[u8]>) -> String {
    ContentDigest::of_bytes(input).to_string()
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
        ContentDigest(self.hasher.finalize().into()).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{ContentDigest, content_digest, sha256_hex};

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

    #[test]
    fn binary_and_composite_digests_are_canonical_and_unambiguous() {
        let digest = ContentDigest::of_bytes(b"abc");
        assert_eq!(ContentDigest::parse(&digest.to_string()), Ok(digest));
        assert!(ContentDigest::parse(&digest.to_string().to_uppercase()).is_err());

        let mut left = ContentDigest::builder(b"workflow-verifier/test/1");
        left.add(b"ab").add(b"c");
        let mut right = ContentDigest::builder(b"workflow-verifier/test/1");
        right.add(b"a").add(b"bc");
        assert_ne!(left.finish(), right.finish());
    }
}
