//! Shared fuzz admission, tested against the production audit path and verifier.
use std::{fs, path::Path};

use crate::Result;

/// The first byte selects the outer storage target and is not an audit byte.
pub fn verify_input(root: &Path, framed_input: &[u8]) -> Result<()> {
    let path = super::audit_log_path(root);
    fs::create_dir_all(path.parent().expect("audit directory"))?;
    fs::write(path, framed_input.get(1..).unwrap_or_default())?;
    super::verify_hash_chain(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_fuzz_input_reaches_audit_decoder_without_selector() {
        let missed = tempfile::tempdir().unwrap();
        // Reproduce the former harness: the verifier never reads this file.
        fs::write(missed.path().join("audit.jsonl"), b"not-json\n").unwrap();
        super::super::verify_hash_chain(missed.path()).unwrap();
        let root = tempfile::tempdir().unwrap();
        // This used to pass because the harness wrote outside the reader's directory.
        assert!(verify_input(root.path(), b"\x04not-json\n").is_err());
        assert_eq!(
            fs::read(super::super::audit_log_path(root.path())).unwrap(),
            b"not-json\n"
        );
        assert!(!root.path().join("audit.jsonl").exists());
    }

    #[test]
    fn storage_fuzz_input_accepts_valid_chain_and_rejects_tampering() {
        let root = tempfile::tempdir().unwrap();
        let mut value = serde_json::json!({
            "schema_version": 2,
            "sequence": 1,
            "prev_record_hash": super::super::genesis_hash(),
        });
        value["record_hash"] = super::super::hash_json_value(&value).unwrap().into();
        let mut input = vec![4];
        input.extend(serde_json::to_vec(&value).unwrap());
        input.push(b'\n');
        verify_input(root.path(), &input).unwrap();
        value["sequence"] = 2.into();
        input.truncate(1);
        input.extend(serde_json::to_vec(&value).unwrap());
        assert!(verify_input(root.path(), &input).is_err());
    }
}
