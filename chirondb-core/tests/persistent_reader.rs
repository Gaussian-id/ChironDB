use std::{fs, io::Read};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chirondb_core::encryption::{self, DEFAULT_CHUNK_SIZE, FileType, Keyring, PersistentFile};

#[test]
fn encrypted_persistent_file_uses_authenticated_ranges_and_streaming_write() {
    let temp = tempfile::tempdir().unwrap();
    let keyring_path = temp.path().join("keyring.json");
    fs::write(
        &keyring_path,
        serde_json::json!({
            "version": 1,
            "active_key_id": "test-key",
            "keys": [{
                "id": "test-key",
                "key_base64": STANDARD.encode([7_u8; 32]),
            }],
        })
        .to_string(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&keyring_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    encryption::install_process_keyring(Keyring::load(&keyring_path).unwrap(), false).unwrap();

    let plaintext = (0..DEFAULT_CHUNK_SIZE * 3 + 17)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let path = temp.path().join("staged.bin");
    fs::write(&path, &plaintext).unwrap();
    encryption::encrypt_file_in_place(&path, FileType::Segment).unwrap();

    let file = PersistentFile::open(&path).unwrap();
    assert!(file.is_encrypted());
    assert_eq!(file.len(), plaintext.len());
    let start = DEFAULT_CHUNK_SIZE - 11;
    let end = DEFAULT_CHUNK_SIZE * 2 + 13;
    assert_eq!(
        &*file.read_range(start..end).unwrap(),
        &plaintext[start..end]
    );
    let mut bounded = file.reader();
    let mut oversized_buffer = vec![0_u8; plaintext.len()];
    assert_eq!(
        bounded.read(&mut oversized_buffer).unwrap(),
        DEFAULT_CHUNK_SIZE,
        "one reader call must not materialize more than one bounded chunk"
    );
    let mut streamed = Vec::new();
    file.reader().read_to_end(&mut streamed).unwrap();
    assert_eq!(streamed, plaintext);
    assert!(encryption::map_persistent(&path).is_err());

    let encoded = fs::read(&path).unwrap();
    let trailing_path = temp.path().join("trailing.bin");
    let mut trailing = encoded.clone();
    trailing.push(0xff);
    fs::write(&trailing_path, trailing).unwrap();
    assert!(PersistentFile::open(&trailing_path).is_err());

    let corrupt_path = temp.path().join("corrupt.bin");
    let mut corrupt = encoded;
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(&corrupt_path, corrupt).unwrap();
    let corrupt_file = PersistentFile::open(&corrupt_path).unwrap();
    assert!(
        corrupt_file
            .read_range(DEFAULT_CHUNK_SIZE * 3..plaintext.len())
            .is_err()
    );
}
