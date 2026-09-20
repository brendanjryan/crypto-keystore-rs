#![cfg(any(feature = "ethereum", feature = "solana"))]
#[path = "support/fuzz_cases.rs"]
mod cases;

#[test]
fn replay_fuzz_corpora() {
    for (directory, exercise) in [
        ("imports", cases::imports as fn(&[u8])),
        ("authenticated", cases::authenticated as fn(&[u8])),
    ] {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/corpus")
            .join(directory);
        let mut count = 0;
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                exercise(&std::fs::read(path).unwrap());
                count += 1;
            }
        }
        assert!(count > 0, "empty {directory} corpus");
    }
}

#[test]
fn every_authenticated_field_is_checked_for_both_kdfs() {
    for kdf in 0..2 {
        for field in 0..8 {
            cases::authenticated(&[kdf, 7, field, b'p', 0, 0xff]);
        }
    }
}
