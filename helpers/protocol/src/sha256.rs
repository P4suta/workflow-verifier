// SHA-256's published notation uses eight one-letter working variables and
// fixed-width hexadecimal constants. Keeping that correspondence reviewable is
// safer than cosmetically renaming or regrouping the reference algorithm. The
// chunk iterators also preserve the workspace's Rust 1.85 MSRV; `as_chunks`
// is newer than that contract even though current Clippy recommends it.
#![allow(unknown_lints)]
#![allow(
    clippy::chunks_exact_to_as_chunks,
    clippy::many_single_char_names,
    clippy::unreadable_literal
)]

use crate::SHA256_HEX_DIGITS;

// Fixed by FIPS 180-4 section 5.1.1 and section 6.2.2.
const SHA256_BLOCK_BYTES: usize = 64;
const SHA256_DOUBLE_BLOCK_BYTES: usize = SHA256_BLOCK_BYTES * 2;
const SHA256_STATE_WORDS: usize = 8;
const SHA256_ROUNDS: usize = 64;
const SHA256_INITIAL_SCHEDULE_WORDS: usize = 16;
const SHA256_WORD_BYTES: usize = 4;
const SHA256_LENGTH_FIELD_BYTES: usize = 8;
const SHA256_BITS_PER_BYTE: u64 = 8;
const SHA256_PADDING_MARKER: u8 = 0x80;
const SHA256_HEX_DIGITS_PER_WORD: usize = 8;
const SCHEDULE_OFFSET_16: usize = 16;
const SCHEDULE_OFFSET_15: usize = 15;
const SCHEDULE_OFFSET_7: usize = 7;
const SCHEDULE_OFFSET_2: usize = 2;

const K: [u32; SHA256_ROUNDS] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INITIAL_STATE: [u32; SHA256_STATE_WORDS] = [
    0x6a09e667u32,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
];

fn compress(state: &mut [u32; SHA256_STATE_WORDS], block: &[u8; SHA256_BLOCK_BYTES]) {
    let mut schedule = [0u32; SHA256_ROUNDS];
    for (index, word) in block
        .chunks_exact(SHA256_WORD_BYTES)
        .take(SHA256_INITIAL_SCHEDULE_WORDS)
        .enumerate()
    {
        schedule[index] = u32::from_be_bytes(
            word.try_into()
                .expect("SHA-256 schedule chunks have one word"),
        );
    }
    for index in SHA256_INITIAL_SCHEDULE_WORDS..SHA256_ROUNDS {
        let x = schedule[index - SCHEDULE_OFFSET_15];
        let y = schedule[index - SCHEDULE_OFFSET_2];
        let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
        let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);
        schedule[index] = schedule[index - SCHEDULE_OFFSET_16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - SCHEDULE_OFFSET_7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..SHA256_ROUNDS {
        let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        // The two terms are disjoint, so addition cannot carry and exactly
        // expresses the FIPS 180-4 choice function.
        let choice = (e & f).wrapping_add((!e) & g);
        let temp1 = h
            .wrapping_add(sum1)
            .wrapping_add(choice)
            .wrapping_add(K[index])
            .wrapping_add(schedule[index]);
        let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        // When a and b agree they determine the majority; when they differ c
        // does. These terms are disjoint, so addition cannot carry.
        let majority = (a & b).wrapping_add(c & (a ^ b));
        let temp2 = sum0.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

/// Incremental, allocation-free SHA-256 state for large content-addressed
/// artifacts such as VM disk images.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; SHA256_STATE_WORDS],
    buffer: [u8; SHA256_BLOCK_BYTES],
    buffered: usize,
    byte_length: u64,
}

impl Sha256 {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            buffer: [0; SHA256_BLOCK_BYTES],
            buffered: 0,
            byte_length: 0,
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        self.byte_length = self
            .byte_length
            .wrapping_add(u64::try_from(input.len()).unwrap_or(u64::MAX));
        if self.buffered != 0 {
            let count = input.len().min(SHA256_BLOCK_BYTES - self.buffered);
            self.buffer[self.buffered..self.buffered + count].copy_from_slice(&input[..count]);
            self.buffered += count;
            input = &input[count..];
            if self.buffered == SHA256_BLOCK_BYTES {
                compress(&mut self.state, &self.buffer);
                self.buffered = 0;
            } else {
                return;
            }
        }
        while input.len() >= SHA256_BLOCK_BYTES {
            let mut block = [0_u8; SHA256_BLOCK_BYTES];
            block.copy_from_slice(&input[..SHA256_BLOCK_BYTES]);
            compress(&mut self.state, &block);
            input = &input[SHA256_BLOCK_BYTES..];
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffered = input.len();
    }

    #[must_use]
    pub fn finalize_hex(mut self) -> String {
        let bit_length = self.byte_length.wrapping_mul(SHA256_BITS_PER_BYTE);
        let mut tail = [0_u8; SHA256_DOUBLE_BLOCK_BYTES];
        tail[..self.buffered].copy_from_slice(&self.buffer[..self.buffered]);
        tail[self.buffered] = SHA256_PADDING_MARKER;
        let padding_threshold = SHA256_BLOCK_BYTES - SHA256_LENGTH_FIELD_BYTES;
        let padded_length = if self.buffered < padding_threshold {
            SHA256_BLOCK_BYTES
        } else {
            SHA256_DOUBLE_BLOCK_BYTES
        };
        tail[padded_length - SHA256_LENGTH_FIELD_BYTES..padded_length]
            .copy_from_slice(&bit_length.to_be_bytes());
        for offset in (0..padded_length).step_by(SHA256_BLOCK_BYTES) {
            let mut block = [0_u8; SHA256_BLOCK_BYTES];
            block.copy_from_slice(&tail[offset..offset + SHA256_BLOCK_BYTES]);
            compress(&mut self.state, &block);
        }
        let mut output = String::with_capacity(SHA256_HEX_DIGITS);
        for value in self.state {
            use std::fmt::Write as _;
            let width = SHA256_HEX_DIGITS_PER_WORD;
            write!(&mut output, "{value:0width$x}").expect("writing to String cannot fail");
        }
        output
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn digest(input: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(input);
    digest.finalize_hex()
}

#[cfg(test)]
mod tests {
    #[test]
    fn fips_vector() {
        assert_eq!(
            super::digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn fips_multiblock_padding_vector() {
        assert_eq!(
            super::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }
}
