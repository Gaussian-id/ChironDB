// Each fuzz binary includes this shared module independently and uses only the
// framing helper relevant to that target.
#![allow(dead_code)]

use std::{fs, path::Path};

const MAX_HARNESS_INPUT: usize = 1024 * 1024;
const WAL_HEADER_BYTES: usize = 8;
const RESTORE_JOURNAL_HEADER_BYTES: usize = 20;

pub fn write_wal_input(directory: &Path, input: &[u8]) -> std::io::Result<()> {
    fs::create_dir_all(directory)?;
    fs::write(directory.join("000000.gdwal"), wal_bytes(input))
}

pub fn restore_journal_bytes(input: &[u8]) -> Vec<u8> {
    let input = bounded(input);
    let Some((&mode, payload)) = input.split_first() else {
        return Vec::new();
    };
    if mode != b'F' {
        return input.to_vec();
    }

    let payload_len = u32::try_from(payload.len()).expect("bounded fuzz input");
    let mut frame = Vec::with_capacity(RESTORE_JOURNAL_HEADER_BYTES + payload.len());
    frame.extend_from_slice(b"CHIRRJN1");
    frame.extend_from_slice(&1_u16.to_le_bytes());
    frame.extend_from_slice(&0_u16.to_le_bytes());
    frame.extend_from_slice(&payload_len.to_le_bytes());
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&frame);
    hasher.update(payload);
    frame.extend_from_slice(&hasher.finalize().to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn wal_bytes(input: &[u8]) -> Vec<u8> {
    let input = bounded(input);
    let Some((&mode, payload)) = input.split_first() else {
        return Vec::new();
    };
    if mode != b'F' {
        return input.to_vec();
    }

    let payload_len = u32::try_from(payload.len()).expect("bounded fuzz input");
    let mut frame = Vec::with_capacity(WAL_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&payload_len.to_le_bytes());
    frame.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn bounded(input: &[u8]) -> &[u8] {
    &input[..input.len().min(MAX_HARNESS_INPUT)]
}
