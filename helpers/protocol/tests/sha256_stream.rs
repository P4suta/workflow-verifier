use workflow_verifier_runner_protocol::{Sha256, sha256_hex};

#[test]
fn incremental_sha256_matches_one_shot_across_every_chunk_boundary() {
    let input = (0_u16..1024).flat_map(u16::to_be_bytes).collect::<Vec<_>>();
    let expected = sha256_hex(&input);
    for chunk_size in 1..=129 {
        let mut digest = Sha256::new();
        for chunk in input.chunks(chunk_size) {
            digest.update(chunk);
        }
        assert_eq!(digest.finalize_hex(), expected, "chunk size {chunk_size}");
    }
}

#[test]
fn incremental_sha256_handles_empty_and_exact_blocks() {
    let mut empty = Sha256::new();
    empty.update(&[]);
    assert_eq!(empty.finalize_hex(), sha256_hex(b""));

    let mut blocks = Sha256::new();
    blocks.update(&[0x5a; 64]);
    blocks.update(&[0xa5; 64]);
    assert_eq!(
        blocks.finalize_hex(),
        sha256_hex(&[&[0x5a; 64][..], &[0xa5; 64][..]].concat())
    );
}
