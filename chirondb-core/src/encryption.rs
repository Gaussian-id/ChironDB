//! Versioned application-level encrypted envelope used by durable artifacts.
//!
//! `CHIRENC1` uses a random per-file DEK, AES-256-GCM authenticated chunks,
//! and a KEK from an external keyring only to wrap that DEK. The keyring is
//! deliberately outside the data directory and is never part of snapshots.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, File},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    ops::Range,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use memmap2::Mmap;

use crate::{
    GaussError, Result,
    fs_util::{atomic_write, atomic_write_with, read_exact_bounded},
};

mod admission;
mod range;
pub(crate) use range::AdmittedRange;

pub const MAGIC: &[u8; 8] = b"CHIRENC1";
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
pub(crate) const MAX_ENCRYPTION_CHUNK_SIZE: usize = 4 * 1024 * 1024;
pub const PERSISTENT_CACHE_BYTES: usize = 64 * 1024 * 1024;
const PERSISTENT_PROBATION_BYTES: usize = 8 * 1024 * 1024;
const PERSISTENT_MAIN_BYTES: usize = PERSISTENT_CACHE_BYTES - PERSISTENT_PROBATION_BYTES;
const MAX_KEYRING_BYTES: u64 = 1024 * 1024;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_TREE_KEY_IDS: usize = 32 * 1024;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const FIXED_HEADER_LEN: usize = 8 + 1 + 1 + 2 + 16 + 8 + 4 + NONCE_LEN + 2;

static PROCESS_KEYRING: OnceLock<Arc<Keyring>> = OnceLock::new();
static ENCRYPTION_ENFORCED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static PERSISTENT_CHUNK_CACHE: OnceLock<RwLock<PersistentChunkCache>> = OnceLock::new();
static NEXT_PERSISTENT_CACHE_ID: AtomicU64 = AtomicU64::new(1);
static PERSISTENT_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static PERSISTENT_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
static PERSISTENT_CACHE_DECRYPTED_BYTES: AtomicU64 = AtomicU64::new(0);
static PERSISTENT_CACHE_HIGH_WATER_BYTES: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct PersistentCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub decrypted_bytes: u64,
}

pub fn reset_persistent_cache_stats() {
    PERSISTENT_CACHE_HITS.store(0, Ordering::Relaxed);
    PERSISTENT_CACHE_MISSES.store(0, Ordering::Relaxed);
    PERSISTENT_CACHE_DECRYPTED_BYTES.store(0, Ordering::Relaxed);
}

pub fn persistent_cache_stats() -> PersistentCacheStats {
    PersistentCacheStats {
        hits: PERSISTENT_CACHE_HITS.load(Ordering::Relaxed),
        misses: PERSISTENT_CACHE_MISSES.load(Ordering::Relaxed),
        decrypted_bytes: PERSISTENT_CACHE_DECRYPTED_BYTES.load(Ordering::Relaxed),
    }
}

pub fn persistent_cache_usage_bytes() -> (usize, usize) {
    let current = persistent_chunk_cache()
        .read()
        .map(|cache| cache.bytes)
        .unwrap_or(0);
    (
        current,
        PERSISTENT_CACHE_HIGH_WATER_BYTES.load(Ordering::Relaxed),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FileType {
    Metadata = 1,
    Segment = 2,
    Wal = 3,
    Audit = 4,
    Snapshot = 5,
    Raft = 6,
}

impl TryFrom<u8> for FileType {
    type Error = GaussError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Metadata),
            2 => Ok(Self::Segment),
            3 => Ok(Self::Wal),
            4 => Ok(Self::Audit),
            5 => Ok(Self::Snapshot),
            6 => Ok(Self::Raft),
            _ => Err(GaussError::InvalidRequest(format!(
                "unknown encrypted file type {value}"
            ))),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringDocument {
    version: u8,
    active_key_id: String,
    keys: Vec<KeyDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyDocument {
    id: String,
    key_base64: String,
}

#[derive(Debug)]
pub struct Keyring {
    active_key_id: String,
    keys: HashMap<String, SecretKey>,
    source: PathBuf,
}

#[derive(Debug)]
struct SecretKey(Vec<u8>);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Keyring {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        validate_keyring_permissions(path)?;
        let bytes = read_exact_bounded(path, MAX_KEYRING_BYTES)?;
        let document: KeyringDocument = serde_json::from_slice(&bytes)?;
        if document.version != 1 {
            return Err(GaussError::InvalidRequest(format!(
                "unsupported encryption keyring version {}",
                document.version
            )));
        }
        let mut keys = HashMap::new();
        let mut encoded_id_len = None;
        for entry in document.keys {
            if entry.id.is_empty()
                || entry.id.len() > MAX_KEY_ID_BYTES
                || !entry
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(GaussError::InvalidRequest(
                    "invalid encryption key id".to_string(),
                ));
            }
            if encoded_id_len
                .replace(entry.id.len())
                .is_some_and(|length| length != entry.id.len())
            {
                return Err(GaussError::InvalidRequest(
                    "keyring v1 key IDs must have equal encoded lengths so WAL LSNs remain stable during key rotation"
                        .to_string(),
                ));
            }
            let key = STANDARD.decode(entry.key_base64).map_err(|error| {
                GaussError::InvalidRequest(format!("invalid base64 encryption key: {error}"))
            })?;
            if key.len() != 32 {
                return Err(GaussError::InvalidRequest(format!(
                    "encryption key {} must decode to exactly 32 bytes",
                    entry.id
                )));
            }
            if keys.insert(entry.id.clone(), SecretKey(key)).is_some() {
                return Err(GaussError::InvalidRequest(format!(
                    "duplicate encryption key id {}",
                    entry.id
                )));
            }
        }
        if !keys.contains_key(&document.active_key_id) {
            return Err(GaussError::InvalidRequest(
                "active encryption key id is absent from keyring".to_string(),
            ));
        }
        Ok(Self {
            active_key_id: document.active_key_id,
            keys,
            source: path.to_path_buf(),
        })
    }

    pub fn active_key_id(&self) -> &str {
        &self.active_key_id
    }

    pub fn source(&self) -> &Path {
        &self.source
    }

    fn key(&self, id: &str) -> Result<&[u8]> {
        self.keys
            .get(id)
            .map(|key| key.0.as_slice())
            .ok_or_else(|| {
                GaussError::InvalidRequest(format!("encryption key id {id} is not available"))
            })
    }
}

pub fn install_process_keyring(keyring: Keyring, enforce_encryption: bool) -> Result<()> {
    PROCESS_KEYRING.set(Arc::new(keyring)).map_err(|_| {
        GaussError::InvalidRequest("encryption keyring is already installed".into())
    })?;
    ENCRYPTION_ENFORCED.store(enforce_encryption, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

pub fn encryption_enabled() -> bool {
    PROCESS_KEYRING.get().is_some()
}

pub fn encryption_enforced() -> bool {
    ENCRYPTION_ENFORCED.load(std::sync::atomic::Ordering::SeqCst)
}

/// Bind rebuildable verified-byte caches to the complete decryption context.
/// Changing or removing a historical key must force normal authenticated reads.
pub(crate) fn recovery_context_fingerprint() -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"CHIRON-RECOVERY-KEY-CONTEXT-1");
    hash.update([u8::from(encryption_enforced())]);
    if let Some(keyring) = PROCESS_KEYRING.get() {
        let mut memory = crate::relational::wal_decode::MetadataCharge::default();
        memory.prepare(
            (keyring.keys.len() as u64)
                .checked_mul(32)
                .and_then(|n| n.checked_add(1024))
                .ok_or_else(|| GaussError::ResourceExhausted("key context is too large".into()))?,
        )?;
        let mut keys = Vec::new();
        keys.try_reserve_exact(keyring.keys.len())
            .map_err(|_| GaussError::ResourceExhausted("key context allocation failed".into()))?;
        keys.extend(keyring.keys.iter());
        keys.sort_unstable_by(|a, b| a.0.cmp(b.0));
        hash.update((keys.len() as u64).to_le_bytes());
        hash.update((keyring.active_key_id.len() as u64).to_le_bytes());
        hash.update(keyring.active_key_id.as_bytes());
        for (id, key) in keys {
            hash.update((id.len() as u64).to_le_bytes());
            hash.update(id.as_bytes());
            hash.update(&key.0);
        }
    }
    Ok(hash.finalize().into())
}

pub fn read_persistent(path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path)?;
    match (is_encrypted(&bytes), PROCESS_KEYRING.get()) {
        (true, Some(keyring)) => decrypt_bytes(keyring, &bytes).map(|(_, plaintext)| plaintext),
        (true, None) => Err(GaussError::InvalidRequest(format!(
            "encrypted file {} requires an encryption keyring",
            path.display()
        ))),
        (false, _) if encryption_enforced() => Err(GaussError::InvalidRequest(format!(
            "secure mode refuses plaintext persisted file {}",
            path.display()
        ))),
        (false, _) => Ok(bytes),
    }
}

pub fn atomic_write_persistent(path: &Path, file_type: FileType, plaintext: &[u8]) -> Result<()> {
    let encoded = encode_persistent(file_type, plaintext)?;
    atomic_write(path, &encoded)
}

/// Atomically persist an exact-length stream, encrypting in fixed-size chunks.
/// No plaintext staging file or whole-file buffer is created. Input errors,
/// length mismatches and failures before rename leave the prior file intact.
pub(crate) fn atomic_write_persistent_stream(
    path: &Path,
    file_type: FileType,
    plaintext_len: u64,
    input: impl Read,
) -> Result<()> {
    let keyring = PROCESS_KEYRING.get().map(Arc::as_ref);
    if keyring.is_none() && encryption_enforced() {
        return Err(GaussError::InvalidRequest(
            "secure persistence requires an encryption keyring".into(),
        ));
    }
    write_persistent_stream(path, file_type, plaintext_len, input, keyring)
}

fn write_persistent_stream(
    path: &Path,
    file_type: FileType,
    plaintext_len: u64,
    mut input: impl Read,
    keyring: Option<&Keyring>,
) -> Result<()> {
    atomic_write_with(path, |output| {
        let Some(keyring) = keyring else {
            let copied = std::io::copy(&mut input.by_ref().take(plaintext_len), output)?;
            if copied != plaintext_len {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            return require_stream_end(&mut input);
        };
        let rng = SystemRandom::new();
        let mut dek = Zeroizing::new([0_u8; 32]);
        rng.fill(&mut *dek)
            .map_err(|_| GaussError::InvalidRequest("OS RNG failed".to_string()))?;
        let file_uuid = Uuid::new_v4();
        let mut wrap_nonce = [0_u8; NONCE_LEN];
        rng.fill(&mut wrap_nonce)
            .map_err(|_| GaussError::InvalidRequest("OS RNG failed".to_string()))?;
        let key_id = keyring.active_key_id().as_bytes();
        let mut header = Vec::with_capacity(FIXED_HEADER_LEN + key_id.len() + 32 + TAG_LEN);
        header.extend_from_slice(MAGIC);
        header.push(1);
        header.push(file_type as u8);
        header.extend_from_slice(&(key_id.len() as u16).to_le_bytes());
        header.extend_from_slice(file_uuid.as_bytes());
        header.extend_from_slice(&plaintext_len.to_le_bytes());
        header.extend_from_slice(&(DEFAULT_CHUNK_SIZE as u32).to_le_bytes());
        header.extend_from_slice(&wrap_nonce);
        header.extend_from_slice(&((dek.len() + TAG_LEN) as u16).to_le_bytes());
        header.extend_from_slice(key_id);
        let mut wrapped_dek = dek.to_vec();
        seal_in_place(
            keyring.key(keyring.active_key_id())?,
            wrap_nonce,
            &header,
            &mut wrapped_dek,
        )?;
        output.write_all(&header)?;
        output.write_all(&wrapped_dek)?;
        wrapped_dek.zeroize();

        let mut remaining = plaintext_len;
        let mut index = 0_u32;
        let mut chunk = Zeroizing::new(vec![0_u8; DEFAULT_CHUNK_SIZE]);
        while remaining != 0 {
            let read = remaining.min(DEFAULT_CHUNK_SIZE as u64) as usize;
            input.read_exact(&mut chunk[..read])?;
            let mut ciphertext = Zeroizing::new(chunk[..read].to_vec());
            let aad = chunk_aad(
                file_type,
                file_uuid,
                plaintext_len,
                DEFAULT_CHUNK_SIZE,
                index,
            );
            seal_in_place(&*dek, chunk_nonce(file_uuid, index), &aad, &mut ciphertext)?;
            output.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
            output.write_all(&ciphertext)?;
            chunk[..read].zeroize();
            remaining -= read as u64;
            index = index
                .checked_add(1)
                .ok_or_else(|| corruption("chunk index overflow"))?;
        }
        require_stream_end(&mut input)
    })
}

fn require_stream_end(input: &mut impl Read) -> Result<()> {
    let mut extra = [0_u8; 1];
    loop {
        match input.read(&mut extra) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                return Err(GaussError::InvalidRequest(
                    "persistent stream exceeds declared plaintext length".into(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

/// Encrypt an existing immutable plaintext file without materialising either
/// the plaintext or ciphertext as a whole-file buffer.
pub fn encrypt_file_in_place(path: &Path, file_type: FileType) -> Result<()> {
    if PROCESS_KEYRING.get().is_none() {
        if encryption_enforced() {
            return Err(GaussError::InvalidRequest(
                "secure persistence requires an encryption keyring".into(),
            ));
        }
        return Ok(());
    }
    let mut input = File::open(path)?;
    let plaintext_len = input.metadata()?.len();
    let mut prefix = [0_u8; MAGIC.len()];
    let prefix_len = input.read(&mut prefix)?;
    if prefix_len == MAGIC.len() && prefix == *MAGIC {
        return Ok(());
    }
    input.seek(SeekFrom::Start(0))?;
    atomic_write_persistent_stream(path, file_type, plaintext_len, input)
}

pub fn encode_persistent<'a>(file_type: FileType, plaintext: &'a [u8]) -> Result<Cow<'a, [u8]>> {
    match PROCESS_KEYRING.get() {
        Some(keyring) => encrypt_bytes(keyring, file_type, plaintext).map(Cow::Owned),
        None if encryption_enforced() => Err(GaussError::InvalidRequest(
            "secure persistence requires an encryption keyring".to_string(),
        )),
        None => Ok(Cow::Borrowed(plaintext)),
    }
}

pub fn map_persistent(path: &Path) -> Result<Mmap> {
    let mut file = File::open(path)?;
    let mut prefix = [0_u8; 8];
    let prefix_len = file.read(&mut prefix)?;
    if (prefix_len == MAGIC.len() && prefix == *MAGIC) || encryption_enforced() {
        return Err(GaussError::InvalidRequest(format!(
            "encrypted persisted file {} requires bounded PersistentFile access",
            path.display()
        )));
    }
    // SAFETY: callers receive a read-only map and persisted immutable files
    // are atomically replaced rather than modified in place.
    Ok(unsafe { Mmap::map(&file)? })
}

/// Opens a persistence file as a bounded streaming reader. Encrypted input is
/// authenticated one chunk at a time and never materialized as a whole-file
/// plaintext buffer.
pub fn open_persistent_reader(path: &Path) -> Result<Box<dyn Read>> {
    open_persistent_reader_bounded(path, MAX_ENCRYPTION_CHUNK_SIZE)
}

/// Refuse a larger encryption chunk before allocating or decrypting its body.
/// The reader owns header/layout and retained/replacement chunk admission.
/// The caller owns its output buffer; mmap/cache/range output are separate.
pub(crate) fn open_persistent_reader_bounded(
    path: &Path,
    max_chunk_size: usize,
) -> Result<Box<dyn Read>> {
    let (mut memory, root_bytes) =
        admission::path(path, std::mem::size_of::<EncryptedChunkReader>())?;
    let mut file = File::open(path)?;
    let mut prefix = [0_u8; MAGIC.len()];
    let read = file.read(&mut prefix)?;
    file.seek(SeekFrom::Start(0))?;
    if read == MAGIC.len() && prefix == *MAGIC {
        return Ok(Box::new(EncryptedChunkReader::open(
            file,
            max_chunk_size,
            memory,
            root_bytes,
        )?));
    }
    if encryption_enforced() {
        return Err(GaussError::InvalidRequest(format!(
            "secure mode refuses plaintext persisted file {}",
            path.display()
        )));
    }
    memory.reduce(root_bytes);
    Ok(Box::new(PlainReader {
        file,
        _memory: memory,
    }))
}

struct PlainReader {
    file: File,
    _memory: crate::relational::wal_decode::MetadataCharge,
}
impl Read for PlainReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(output)
    }
}

#[derive(Debug)]
struct CachedChunk {
    bytes: Vec<u8>,
    referenced: AtomicBool,
    // Shared Arc pins keep this lease after eviction; bytes drop first.
    _memory: crate::relational::wal_decode::MetadataCharge,
}

impl CachedChunk {
    fn admitted(bytes: Vec<u8>, mut memory: crate::relational::wal_decode::MetadataCharge) -> Self {
        memory.reduce(bytes.capacity() as u64 + admission::cached_chunk_root_bytes());
        Self {
            bytes,
            referenced: AtomicBool::new(false),
            _memory: memory,
        }
    }

    // Synthetic queue policy fixtures allocate their own input outside the
    // cache. Production chunk construction always uses admitted().
    #[cfg(test)]
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            // A newly admitted chunk is probationary. Only an actual cache
            // hit earns a clock second chance, preventing one-pass graph and
            // quantizer scans from displacing the repeatedly used hot set.
            referenced: AtomicBool::new(false),
            _memory: Default::default(),
        }
    }
}

impl Drop for CachedChunk {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Debug, Default)]
struct PersistentChunkCache {
    chunks: HashMap<(u64, usize), CachedEntry>,
    probation: VecDeque<(u64, usize)>,
    main: VecDeque<(u64, usize)>,
    bytes: usize,
    probation_bytes: usize,
    main_bytes: usize,
    // HashMap::capacity can fall with tombstones without freeing buckets.
    hash_capacity: usize,
    // Capacity remains charged after eviction until the containers are freed.
    _memory: crate::relational::wal_decode::MetadataCharge,
}

#[derive(Debug)]
struct CachedEntry {
    chunk: Arc<CachedChunk>,
}

impl PersistentChunkCache {
    // A clock reference bit keeps hot chunks resident without the O(n) queue
    // mutation that the original exact-LRU hit path performed. Hits need only
    // a shared hash-table lookup plus one relaxed atomic store; eviction work
    // remains amortized O(1) and the process-wide byte ceiling is unchanged.
    fn get(&self, key: (u64, usize)) -> Option<Arc<CachedChunk>> {
        let Some(chunk) = self.chunks.get(&key).map(|entry| entry.chunk.clone()) else {
            PERSISTENT_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        PERSISTENT_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
        chunk.referenced.store(true, Ordering::Relaxed);
        Some(chunk)
    }

    #[cfg(test)]
    fn insert(&mut self, key: (u64, usize), chunk: Arc<CachedChunk>) {
        self.try_insert(key, chunk).unwrap();
    }

    fn try_insert(&mut self, key: (u64, usize), chunk: Arc<CachedChunk>) -> Result<()> {
        // A concurrent reader may have filled the miss while this caller was
        // decrypting. Keep the already-published entry and avoid duplicate
        // queue nodes; this caller can still use its authenticated local Arc.
        if self.chunks.contains_key(&key) {
            return Ok(());
        }
        if self.chunks.capacity() == 0
            && self.probation.capacity() == 0
            && self.main.capacity() == 0
        {
            self._memory = Default::default();
        }
        let peak = admission::cache_containers(self, true)?;
        self._memory.prepare(peak)?;
        self.chunks
            .try_reserve(1)
            .map_err(|_| admission::cache_allocation_error())?;
        self.hash_capacity = self.hash_capacity.max(self.chunks.capacity());
        self.probation
            .try_reserve(1)
            .map_err(|_| admission::cache_allocation_error())?;
        // One large chunk can promote the entire probationary queue. Admit
        // and reserve those moves before any cache/queue publication.
        self.main
            .try_reserve(self.probation.len() + 1)
            .map_err(|_| admission::cache_allocation_error())?;
        self._memory
            .reduce(admission::cache_containers(self, false)?);
        self.bytes = self.bytes.saturating_add(chunk.bytes.len());
        self.probation_bytes = self.probation_bytes.saturating_add(chunk.bytes.len());
        self.chunks.insert(key, CachedEntry { chunk });
        self.probation.push_back(key);
        PERSISTENT_CACHE_HIGH_WATER_BYTES.fetch_max(self.bytes, Ordering::Relaxed);
        self.rebalance();
        if crate::streamer::memory_pressure() {
            self.shrink_to(PERSISTENT_CACHE_BYTES / 2);
            metrics::counter!("chirondb_persistent_cache_pressure_shrinks_total").increment(1);
        }
        Ok(())
    }

    fn rebalance(&mut self) {
        while self.probation_bytes > PERSISTENT_PROBATION_BYTES {
            let Some(key) = self.probation.pop_front() else {
                break;
            };
            let Some(entry) = self.chunks.get_mut(&key) else {
                continue;
            };
            let chunk_bytes = entry.chunk.bytes.len();
            if entry.chunk.referenced.swap(false, Ordering::Relaxed) {
                self.probation_bytes = self.probation_bytes.saturating_sub(chunk_bytes);
                self.main_bytes = self.main_bytes.saturating_add(chunk_bytes);
                self.main.push_back(key);
            } else if let Some(entry) = self.chunks.remove(&key) {
                self.probation_bytes = self.probation_bytes.saturating_sub(entry.chunk.bytes.len());
                self.bytes = self.bytes.saturating_sub(entry.chunk.bytes.len());
            }
        }
        while self.main_bytes > PERSISTENT_MAIN_BYTES {
            let Some(key) = self.main.pop_front() else {
                break;
            };
            let Some(entry) = self.chunks.get(&key) else {
                continue;
            };
            if entry.chunk.referenced.swap(false, Ordering::Relaxed) {
                self.main.push_back(key);
                continue;
            }
            if let Some(entry) = self.chunks.remove(&key) {
                self.main_bytes = self.main_bytes.saturating_sub(entry.chunk.bytes.len());
                self.bytes = self.bytes.saturating_sub(entry.chunk.bytes.len());
            }
        }
    }

    fn remove_file(&mut self, cache_id: u64) {
        self.probation.retain(|key| key.0 != cache_id);
        self.main.retain(|key| key.0 != cache_id);
        self.chunks.retain(|key, _| key.0 != cache_id);
        self.probation_bytes = self
            .probation
            .iter()
            .filter_map(|key| self.chunks.get(key))
            .map(|entry| entry.chunk.bytes.len())
            .sum();
        self.main_bytes = self
            .main
            .iter()
            .filter_map(|key| self.chunks.get(key))
            .map(|entry| entry.chunk.bytes.len())
            .sum();
        self.bytes = self.probation_bytes.saturating_add(self.main_bytes);
        self.release_empty_containers();
    }

    fn shrink_to(&mut self, target_bytes: usize) {
        while self.bytes > target_bytes {
            if let Some(key) = self.probation.pop_front() {
                if let Some(entry) = self.chunks.remove(&key) {
                    let bytes = entry.chunk.bytes.len();
                    self.probation_bytes = self.probation_bytes.saturating_sub(bytes);
                    self.bytes = self.bytes.saturating_sub(bytes);
                }
                continue;
            }
            let Some(key) = self.main.pop_front() else {
                break;
            };
            if let Some(entry) = self.chunks.remove(&key) {
                let bytes = entry.chunk.bytes.len();
                self.main_bytes = self.main_bytes.saturating_sub(bytes);
                self.bytes = self.bytes.saturating_sub(bytes);
            }
        }
        self.release_empty_containers();
    }

    fn release_empty_containers(&mut self) {
        if self.chunks.is_empty() {
            drop(std::mem::take(&mut self.chunks));
            drop(std::mem::take(&mut self.probation));
            drop(std::mem::take(&mut self.main));
            self.hash_capacity = 0;
            self._memory.reduce(0);
        }
    }
}

fn persistent_chunk_cache() -> &'static RwLock<PersistentChunkCache> {
    PERSISTENT_CHUNK_CACHE.get_or_init(|| RwLock::new(PersistentChunkCache::default()))
}

#[derive(Debug)]
enum PersistentStorage {
    Plain(Mmap),
    Encrypted {
        ciphertext: Mmap,
        layout: EncryptedLayout,
    },
}

/// Bounded reader for immutable persisted files.
///
/// Plaintext compatibility files retain zero-copy mmap behavior. Encrypted
/// files authenticate and decrypt only the chunks touched by a range or
/// streaming read; no plaintext whole-file anonymous mapping is created.
#[derive(Debug)]
pub struct PersistentFile {
    path: PathBuf,
    len: usize,
    cache_id: u64,
    storage: PersistentStorage,
    // Last: mapping/path/layout owners die before their root reservation.
    _memory: crate::relational::wal_decode::MetadataCharge,
}

impl PersistentFile {
    pub fn open(path: &Path) -> Result<Self> {
        let (mut memory, root_bytes) = admission::path(path, std::mem::size_of::<Self>())?;
        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len();
        let mut prefix = [0_u8; MAGIC.len()];
        let prefix_len = file.read(&mut prefix)?;
        if prefix_len == MAGIC.len() && prefix == *MAGIC {
            if file_len < FIXED_HEADER_LEN as u64 {
                return Err(corruption("truncated encrypted header"));
            }
            let header = read_encrypted_header(&mut file)?;
            let layout = EncryptedLayout::from_header(&header)?;
            let len = usize::try_from(layout.info().plaintext_len)
                .map_err(|_| corruption("plaintext length exceeds usize"))?;
            let expected_encoded_len = if layout.chunk_count() == 0 {
                layout.body_offset as u64
            } else {
                layout.encrypted_chunk_range(layout.chunk_count() - 1)?.end
            };
            if expected_encoded_len != file_len {
                return Err(corruption("encrypted file length mismatch"));
            }
            // The mapping contains only envelope metadata and ciphertext. It
            // lets the OS page ciphertext normally while authenticated
            // plaintext remains confined to the bounded chunk cache.
            let ciphertext = unsafe { Mmap::map(&file)? };
            let path = path.to_path_buf();
            memory.reduce(root_bytes);
            return Ok(Self {
                path,
                len,
                cache_id: NEXT_PERSISTENT_CACHE_ID.fetch_add(1, Ordering::Relaxed),
                storage: PersistentStorage::Encrypted { ciphertext, layout },
                _memory: memory,
            });
        }
        if encryption_enforced() {
            return Err(GaussError::InvalidRequest(format!(
                "secure mode refuses plaintext persisted file {}",
                path.display()
            )));
        }
        file.seek(SeekFrom::Start(0))?;
        // SAFETY: persisted immutable files are atomically replaced instead
        // of being modified while readers hold a read-only mapping.
        let mmap = unsafe { Mmap::map(&file)? };
        let path = path.to_path_buf();
        memory.reduce(root_bytes);
        Ok(Self {
            path,
            len: mmap.len(),
            cache_id: 0,
            storage: PersistentStorage::Plain(mmap),
            _memory: memory,
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self.storage, PersistentStorage::Encrypted { .. })
    }

    pub fn read_range(&self, range: Range<usize>) -> Result<Cow<'_, [u8]>> {
        // Public Cow compatibility cannot carry the internal output lease.
        self.read_range_admitted(range)
            .map(AdmittedRange::into_compat)
    }

    pub(crate) fn read_range_admitted(&self, range: Range<usize>) -> Result<AdmittedRange<'_>> {
        if range.start > range.end || range.end > self.len {
            return Err(GaussError::InvalidRequest(format!(
                "persisted range {}..{} is outside {} ({} bytes)",
                range.start,
                range.end,
                self.path.display(),
                self.len
            )));
        }
        match &self.storage {
            PersistentStorage::Plain(mmap) => Ok(AdmittedRange::borrowed(&mmap[range])),
            PersistentStorage::Encrypted { ciphertext, layout } => {
                if range.is_empty() {
                    return Ok(AdmittedRange::owned(Vec::new(), Default::default()));
                }
                let chunk_size = layout.info().chunk_size;
                let first = range.start / chunk_size;
                let last = (range.end - 1) / chunk_size;
                // Tuple fields drop in order, including on a late chunk failure.
                let mut output = AdmittedRange::buffer(range.end - range.start)?;
                for index in first..=last {
                    let chunk = self.encrypted_chunk(ciphertext, layout, index)?;
                    let chunk_start = index
                        .checked_mul(chunk_size)
                        .ok_or_else(|| corruption("plaintext chunk offset overflow"))?;
                    let copy_start = range.start.saturating_sub(chunk_start);
                    let copy_end =
                        range.end.min(chunk_start.saturating_add(chunk.bytes.len())) - chunk_start;
                    output.0.extend_from_slice(
                        chunk
                            .bytes
                            .get(copy_start..copy_end)
                            .ok_or_else(|| corruption("plaintext chunk slice is out of bounds"))?,
                    );
                }
                if output.0.len() != range.end - range.start {
                    output.0.zeroize();
                    return Err(corruption("plaintext range length mismatch"));
                }
                Ok(AdmittedRange::owned(output.0, output.1))
            }
        }
    }

    pub fn reader(&self) -> PersistentReader<'_> {
        PersistentReader {
            file: self,
            position: 0,
        }
    }

    pub fn reader_at(&self, position: usize) -> Result<PersistentReader<'_>> {
        if position > self.len {
            return Err(GaussError::InvalidRequest(format!(
                "persisted reader offset exceeds {}",
                self.path.display()
            )));
        }
        Ok(PersistentReader {
            file: self,
            position,
        })
    }

    pub fn crc32(&self, range: Range<usize>) -> Result<u32> {
        if range.start > range.end || range.end > self.len {
            return Err(GaussError::InvalidRequest(
                "persisted CRC range is out of bounds".to_string(),
            ));
        }
        let mut hasher = crc32fast::Hasher::new();
        let mut offset = range.start;
        while offset < range.end {
            let end = range.end.min(offset.saturating_add(DEFAULT_CHUNK_SIZE));
            hasher.update(&self.read_range_admitted(offset..end)?);
            offset = end;
        }
        Ok(hasher.finalize())
    }

    fn encrypted_chunk(
        &self,
        ciphertext: &Mmap,
        layout: &EncryptedLayout,
        index: usize,
    ) -> Result<Arc<CachedChunk>> {
        let key = (self.cache_id, index);
        if let Some(chunk) = persistent_chunk_cache()
            .read()
            .expect("persistent chunk cache poisoned")
            .get(key)
        {
            return Ok(chunk);
        }
        let range = layout.encrypted_chunk_range(index)?;
        let start = usize::try_from(range.start)
            .map_err(|_| corruption("encrypted chunk offset exceeds usize"))?;
        let end = usize::try_from(range.end)
            .map_err(|_| corruption("encrypted chunk offset exceeds usize"))?;
        let frame = ciphertext
            .get(start..end)
            .ok_or_else(|| corruption("encrypted chunk frame is out of bounds"))?;
        let memory = admission::cached_chunk(frame.len())?;
        let plaintext = layout.decrypt_chunk_frame(index, frame)?;
        PERSISTENT_CACHE_DECRYPTED_BYTES.fetch_add(plaintext.len() as u64, Ordering::Relaxed);
        let chunk = Arc::new(CachedChunk::admitted(plaintext, memory));
        persistent_chunk_cache()
            .write()
            .expect("persistent chunk cache poisoned")
            .try_insert(key, chunk.clone())?;
        Ok(chunk)
    }
}

impl Drop for PersistentFile {
    fn drop(&mut self) {
        if self.cache_id != 0
            && let Ok(mut cache) = persistent_chunk_cache().write()
        {
            cache.remove_file(self.cache_id);
        }
    }
}

pub struct PersistentReader<'a> {
    file: &'a PersistentFile,
    position: usize,
}

impl Read for PersistentReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() || self.position == self.file.len {
            return Ok(0);
        }
        let end = self.file.len.min(
            self.position
                .saturating_add(buffer.len().min(DEFAULT_CHUNK_SIZE)),
        );
        let bytes = self
            .file
            .read_range_admitted(self.position..end)
            .map_err(std::io::Error::other)?;
        buffer[..bytes.len()].copy_from_slice(&bytes);
        self.position = end;
        Ok(bytes.len())
    }
}

pub fn decode_persistent<'a>(bytes: &'a [u8]) -> Result<Cow<'a, [u8]>> {
    if is_encrypted(bytes) {
        let keyring = PROCESS_KEYRING.get().ok_or_else(|| {
            GaussError::InvalidRequest("encrypted bytes require an encryption keyring".to_string())
        })?;
        return decrypt_bytes(keyring, bytes).map(|(_, plaintext)| Cow::Owned(plaintext));
    }
    if encryption_enforced() {
        return Err(GaussError::InvalidRequest(
            "secure mode refuses plaintext persisted bytes".to_string(),
        ));
    }
    Ok(Cow::Borrowed(bytes))
}

/// Reject an expanded envelope length before decrypt_bytes allocates output.
/// Chiron encryption does not compress: plaintext cannot exceed its frame.
pub(crate) fn decode_persistent_bounded(bytes: &[u8], limit: usize) -> Result<Cow<'_, [u8]>> {
    if is_encrypted(bytes) && parse_header(bytes)?.info.plaintext_len > limit as u64 {
        return Err(corruption("encrypted plaintext exceeds admitted frame"));
    }
    decode_persistent(bytes)
}

/// Audit recovery may discard only a structurally incomplete final envelope.
/// A complete header authenticates before any body-length decision; complete
/// chunks authenticate before truncation is reported. Missing keys never
/// become permission to truncate data. The caller admits input/decrypt overlap.
pub(crate) fn audit_frame_is_truncated(bytes: &[u8], limit: usize) -> Result<bool> {
    let keyring = PROCESS_KEYRING.get().ok_or_else(|| {
        GaussError::InvalidRequest("encrypted bytes require an encryption keyring".into())
    })?;
    if bytes.len() < MAGIC.len() {
        return if MAGIC.starts_with(bytes) {
            Ok(true)
        } else {
            Err(corruption("missing CHIRENC1 header"))
        };
    }
    if !bytes.starts_with(MAGIC) {
        return Err(corruption("missing CHIRENC1 header"));
    }
    if bytes.len() > 8 && bytes[8] != 1 {
        return Err(corruption("unsupported encrypted envelope version"));
    }
    if bytes.len() > 9 && FileType::try_from(bytes[9])? != FileType::Audit {
        return Err(corruption("encrypted audit frame has another file type"));
    }
    if bytes.len() < FIXED_HEADER_LEN {
        return Ok(true);
    }
    let parsed = match parse_header(bytes) {
        Ok(parsed) => parsed,
        Err(GaussError::InvalidRequest(message))
            if message == "encrypted envelope corruption: truncated encrypted header" =>
        {
            return Ok(true);
        }
        Err(error) => return Err(error),
    };
    if parsed.info.plaintext_len > limit as u64 {
        return Err(corruption("encrypted plaintext exceeds admitted frame"));
    }
    match decrypt_bytes(keyring, bytes) {
        Ok(_) => Ok(false),
        Err(GaussError::InvalidRequest(message))
            if matches!(
                message.as_str(),
                "encrypted envelope corruption: truncated encrypted chunk length"
                    | "encrypted envelope corruption: truncated encrypted chunk"
                    | "encrypted envelope corruption: plaintext length mismatch"
            ) =>
        {
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeInfo {
    pub file_type: FileType,
    pub key_id: String,
    pub file_uuid: Uuid,
    pub plaintext_len: u64,
    pub chunk_size: usize,
}

/// Parsed authenticated envelope metadata plus its unwrapped per-file DEK.
/// Used by bounded random-access readers so large encrypted indexes never need
/// a plaintext whole-file mapping or temporary file.
pub struct EncryptedLayout {
    info: EnvelopeInfo,
    body_offset: usize,
    dek: Vec<u8>,
    _memory: crate::relational::wal_decode::MetadataCharge,
}

impl std::fmt::Debug for EncryptedLayout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedLayout")
            .field("info", &self.info)
            .field("body_offset", &self.body_offset)
            .finish_non_exhaustive()
    }
}

impl Drop for EncryptedLayout {
    fn drop(&mut self) {
        self.dek.zeroize();
    }
}

impl EncryptedLayout {
    pub(crate) fn from_file_header(file: &mut File) -> Result<Self> {
        let header = read_encrypted_header(file)?;
        Self::from_header(&header)
    }

    pub fn from_header(envelope_header: &[u8]) -> Result<Self> {
        let keyring = PROCESS_KEYRING.get().ok_or_else(|| {
            GaussError::InvalidRequest("encrypted bytes require an encryption keyring".to_string())
        })?;
        Self::from_header_with_keyring(keyring, envelope_header)
    }

    fn from_header_with_keyring(keyring: &Keyring, envelope_header: &[u8]) -> Result<Self> {
        let memory = admission::layout(envelope_header)?;
        let parsed = parse_header(envelope_header)?;
        let mut dek = Zeroizing::new(parsed.wrapped_dek.to_vec());
        open_in_place(
            keyring.key(&parsed.info.key_id)?,
            parsed.wrap_nonce,
            parsed.aad_header,
            &mut dek,
        )?;
        if dek.len() != 32 {
            dek.zeroize();
            return Err(corruption("invalid unwrapped DEK length"));
        }
        Ok(Self {
            info: parsed.info,
            body_offset: parsed.body_offset,
            dek: std::mem::take(&mut *dek),
            _memory: memory,
        })
    }

    pub fn info(&self) -> &EnvelopeInfo {
        &self.info
    }

    pub fn chunk_count(&self) -> usize {
        usize::try_from(self.info.plaintext_len)
            .unwrap_or(usize::MAX)
            .div_ceil(self.info.chunk_size)
    }

    pub fn encrypted_chunk_range(&self, index: usize) -> Result<std::ops::Range<u64>> {
        if index >= self.chunk_count() || index > u32::MAX as usize {
            return Err(corruption("encrypted chunk index out of bounds"));
        }
        let stride = self
            .info
            .chunk_size
            .checked_add(TAG_LEN + 4)
            .ok_or_else(|| corruption("encrypted chunk stride overflow"))?;
        let start = self
            .body_offset
            .checked_add(
                index
                    .checked_mul(stride)
                    .ok_or_else(|| corruption("encrypted chunk offset overflow"))?,
            )
            .ok_or_else(|| corruption("encrypted chunk offset overflow"))?;
        let plaintext_start = index
            .checked_mul(self.info.chunk_size)
            .ok_or_else(|| corruption("plaintext chunk offset overflow"))?;
        let remaining = usize::try_from(self.info.plaintext_len)
            .map_err(|_| corruption("plaintext length exceeds usize"))?
            .saturating_sub(plaintext_start);
        let plaintext_len = remaining.min(self.info.chunk_size);
        let end = start
            .checked_add(4 + plaintext_len + TAG_LEN)
            .ok_or_else(|| corruption("encrypted chunk end overflow"))?;
        Ok(start as u64..end as u64)
    }

    pub fn decrypt_chunk_frame(&self, index: usize, frame: &[u8]) -> Result<Vec<u8>> {
        if frame.len() < 4 {
            return Err(corruption("truncated encrypted chunk length"));
        }
        let encoded_len = u32::from_le_bytes(frame[..4].try_into().expect("chunk length")) as usize;
        if encoded_len < TAG_LEN || encoded_len > self.info.chunk_size.saturating_add(TAG_LEN) {
            return Err(corruption("invalid encrypted chunk length"));
        }
        if frame.len() != encoded_len + 4 {
            return Err(corruption("encrypted chunk frame length mismatch"));
        }
        let mut chunk = frame[4..].to_vec();
        let index = u32::try_from(index).map_err(|_| corruption("chunk index exceeds u32"))?;
        let aad = chunk_aad(
            self.info.file_type,
            self.info.file_uuid,
            self.info.plaintext_len,
            self.info.chunk_size,
            index,
        );
        let result = open_in_place(
            &self.dek,
            chunk_nonce(self.info.file_uuid, index),
            &aad,
            &mut chunk,
        );
        if let Err(error) = result {
            chunk.zeroize();
            return Err(error);
        }
        Ok(chunk)
    }
}

fn read_encrypted_header(file: &mut File) -> Result<admission::Header> {
    admission::header(file)
}

struct EncryptedChunkReader {
    file: File,
    layout: EncryptedLayout,
    encoded_len: u64,
    next_chunk: usize,
    encoded_end: u64,
    plaintext_read: u64,
    chunk: Vec<u8>,
    chunk_offset: usize,
    _memory: crate::relational::wal_decode::MetadataCharge,
}

impl EncryptedChunkReader {
    fn open(
        mut file: File,
        max_chunk_size: usize,
        mut memory: crate::relational::wal_decode::MetadataCharge,
        root_bytes: u64,
    ) -> Result<Self> {
        let encoded_len = file.metadata()?.len();
        let header = read_encrypted_header(&mut file)?;
        let chunk_size =
            u32::from_le_bytes(header[36..40].try_into().expect("chunk size")) as usize;
        if chunk_size > max_chunk_size && chunk_size <= MAX_ENCRYPTION_CHUNK_SIZE {
            return Err(GaussError::ResourceExhausted(
                "encrypted reader chunk exceeds admitted memory".into(),
            ));
        }
        let layout = EncryptedLayout::from_header(&header)?;
        let encoded_end = layout.body_offset as u64;
        // Old retained chunk, encoded frame and freshly decrypted replacement
        // can coexist. Admit the peak once, before any body allocation/read.
        let overlap = layout
            .info()
            .plaintext_len
            .min(chunk_size as u64)
            .checked_add((4 + TAG_LEN) as u64)
            .and_then(|n| n.checked_mul(3))
            .and_then(|n| n.checked_add(root_bytes))
            .ok_or_else(|| {
                GaussError::ResourceExhausted("encrypted stream memory overflow".into())
            })?;
        memory.prepare(overlap)?;
        Ok(Self {
            file,
            layout,
            encoded_len,
            next_chunk: 0,
            encoded_end,
            plaintext_read: 0,
            chunk: Vec::new(),
            chunk_offset: 0,
            _memory: memory,
        })
    }

    fn load_chunk(&mut self) -> std::io::Result<bool> {
        self.chunk.zeroize();
        self.chunk.clear();
        self.chunk_offset = 0;
        if self.next_chunk == self.layout.chunk_count() {
            if self.plaintext_read != self.layout.info().plaintext_len
                || self.encoded_end != self.encoded_len
            {
                return Err(invalid_data("encrypted file length mismatch"));
            }
            return Ok(false);
        }
        let range = self
            .layout
            .encrypted_chunk_range(self.next_chunk)
            .map_err(invalid_data_error)?;
        if range.end > self.encoded_len {
            return Err(invalid_data("truncated encrypted chunk frame"));
        }
        let frame_len = usize::try_from(range.end - range.start)
            .map_err(|_| invalid_data("encrypted chunk frame exceeds usize"))?;
        let mut frame = Zeroizing::new(vec![0_u8; frame_len]);
        self.file.seek(SeekFrom::Start(range.start))?;
        self.file.read_exact(&mut frame)?;
        self.chunk = self
            .layout
            .decrypt_chunk_frame(self.next_chunk, &frame)
            .map_err(invalid_data_error)?;
        self.encoded_end = range.end;
        self.next_chunk += 1;
        Ok(true)
    }
}

impl Read for EncryptedChunkReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.chunk_offset == self.chunk.len() && !self.load_chunk()? {
            return Ok(0);
        }
        let available = &self.chunk[self.chunk_offset..];
        let copied = available.len().min(output.len());
        output[..copied].copy_from_slice(&available[..copied]);
        self.chunk_offset += copied;
        self.plaintext_read = self
            .plaintext_read
            .checked_add(copied as u64)
            .ok_or_else(|| invalid_data("plaintext read offset overflow"))?;
        Ok(copied)
    }
}

impl Drop for EncryptedChunkReader {
    fn drop(&mut self) {
        self.chunk.zeroize();
    }
}

fn invalid_data(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_string())
}

fn invalid_data_error(error: GaussError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct EncryptionTreeReport {
    pub encrypted_files: u64,
    pub plaintext_files: u64,
    pub encrypted_bytes: u64,
    pub plaintext_bytes: u64,
    pub key_ids: HashSet<String>,
    /// Bounded diagnostic sample; the counts above remain authoritative.
    pub plaintext_paths: Vec<String>,
}

pub fn is_encrypted(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

pub fn encrypt_bytes(keyring: &Keyring, file_type: FileType, plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_bytes_with_chunk_size(keyring, file_type, plaintext, DEFAULT_CHUNK_SIZE)
}

fn encrypt_bytes_with_chunk_size(
    keyring: &Keyring,
    file_type: FileType,
    plaintext: &[u8],
    chunk_size: usize,
) -> Result<Vec<u8>> {
    if chunk_size == 0 || chunk_size > u32::MAX as usize {
        return Err(GaussError::InvalidRequest(
            "invalid encryption chunk size".to_string(),
        ));
    }
    let rng = SystemRandom::new();
    let mut dek = [0_u8; 32];
    rng.fill(&mut dek)
        .map_err(|_| GaussError::InvalidRequest("OS RNG failed".to_string()))?;
    let file_uuid = Uuid::new_v4();
    let mut wrap_nonce = [0_u8; NONCE_LEN];
    rng.fill(&mut wrap_nonce)
        .map_err(|_| GaussError::InvalidRequest("OS RNG failed".to_string()))?;
    let key_id = keyring.active_key_id().as_bytes();

    let mut aad_header = Vec::with_capacity(FIXED_HEADER_LEN + key_id.len());
    aad_header.extend_from_slice(MAGIC);
    aad_header.push(1);
    aad_header.push(file_type as u8);
    aad_header.extend_from_slice(&(key_id.len() as u16).to_le_bytes());
    aad_header.extend_from_slice(file_uuid.as_bytes());
    aad_header.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());
    aad_header.extend_from_slice(&(chunk_size as u32).to_le_bytes());
    aad_header.extend_from_slice(&wrap_nonce);
    aad_header.extend_from_slice(&((dek.len() + TAG_LEN) as u16).to_le_bytes());
    aad_header.extend_from_slice(key_id);

    let mut wrapped_dek = dek.to_vec();
    seal_in_place(
        keyring.key(keyring.active_key_id())?,
        wrap_nonce,
        &aad_header,
        &mut wrapped_dek,
    )?;
    let mut header = aad_header;
    header.extend_from_slice(&wrapped_dek);
    let chunk_count = plaintext.len().div_ceil(chunk_size);
    if chunk_count > u32::MAX as usize {
        dek.zeroize();
        return Err(GaussError::InvalidRequest(
            "encrypted file has too many chunks".to_string(),
        ));
    }
    let mut output = Vec::with_capacity(
        header
            .len()
            .saturating_add(plaintext.len())
            .saturating_add(chunk_count.saturating_mul(TAG_LEN + 4)),
    );
    output.extend_from_slice(&header);
    for (index, chunk) in plaintext.chunks(chunk_size).enumerate() {
        let mut ciphertext = chunk.to_vec();
        let nonce = chunk_nonce(file_uuid, index as u32);
        let aad = chunk_aad(
            file_type,
            file_uuid,
            plaintext.len() as u64,
            chunk_size,
            index as u32,
        );
        seal_in_place(&dek, nonce, &aad, &mut ciphertext)?;
        output.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
        output.extend_from_slice(&ciphertext);
    }
    dek.zeroize();
    Ok(output)
}

pub fn decrypt_bytes(keyring: &Keyring, envelope: &[u8]) -> Result<(EnvelopeInfo, Vec<u8>)> {
    let parsed = parse_header(envelope)?;
    let kek = keyring.key(&parsed.info.key_id)?;
    let mut dek = parsed.wrapped_dek.to_vec();
    open_in_place(kek, parsed.wrap_nonce, parsed.aad_header, &mut dek)?;
    if dek.len() != 32 {
        dek.zeroize();
        return Err(GaussError::InvalidRequest(
            "invalid unwrapped DEK length".to_string(),
        ));
    }
    let expected_len = usize::try_from(parsed.info.plaintext_len).map_err(|_| {
        GaussError::InvalidRequest("encrypted plaintext length exceeds usize".to_string())
    })?;
    let mut plaintext = Vec::with_capacity(expected_len);
    let mut offset = parsed.body_offset;
    let mut index = 0_u32;
    while offset < envelope.len() {
        let len_end = offset
            .checked_add(4)
            .ok_or_else(|| corruption("chunk length overflow"))?;
        if len_end > envelope.len() {
            return Err(corruption("truncated encrypted chunk length"));
        }
        let len = u32::from_le_bytes(envelope[offset..len_end].try_into().expect("chunk length"))
            as usize;
        if len < TAG_LEN || len > parsed.info.chunk_size.saturating_add(TAG_LEN) {
            return Err(corruption("invalid encrypted chunk length"));
        }
        let end = len_end
            .checked_add(len)
            .ok_or_else(|| corruption("chunk end overflow"))?;
        if end > envelope.len() {
            return Err(corruption("truncated encrypted chunk"));
        }
        let mut chunk = envelope[len_end..end].to_vec();
        let aad = chunk_aad(
            parsed.info.file_type,
            parsed.info.file_uuid,
            parsed.info.plaintext_len,
            parsed.info.chunk_size,
            index,
        );
        open_in_place(
            &dek,
            chunk_nonce(parsed.info.file_uuid, index),
            &aad,
            &mut chunk,
        )?;
        // The authenticated declared length is the output allocation bound.
        // Reject excess chunks before extend could grow past that reservation.
        if chunk.len() > expected_len.saturating_sub(plaintext.len()) {
            dek.zeroize();
            return Err(corruption("encrypted plaintext exceeds declared length"));
        }
        plaintext.extend_from_slice(&chunk);
        offset = end;
        index = index
            .checked_add(1)
            .ok_or_else(|| corruption("chunk index overflow"))?;
    }
    dek.zeroize();
    if plaintext.len() != expected_len {
        plaintext.zeroize();
        return Err(corruption("plaintext length mismatch"));
    }
    Ok((parsed.info, plaintext))
}

pub fn encrypt_file(
    keyring: &Keyring,
    file_type: FileType,
    source: &Path,
    destination: &Path,
) -> Result<()> {
    let plaintext = fs::read(source)?;
    let envelope = encrypt_bytes(keyring, file_type, &plaintext)?;
    atomic_write(destination, &envelope)
}

pub fn inspect_file(path: &Path) -> Result<EnvelopeInfo> {
    let bytes = fs::read(path)?;
    Ok(parse_header(&bytes)?.info)
}

pub fn persistent_plaintext_len(path: &Path) -> Result<u64> {
    let (_memory, _) = admission::path(path, std::mem::size_of::<File>())?;
    let mut file = File::open(path)?;
    let mut prefix = [0_u8; 8];
    let read = file.read(&mut prefix)?;
    if read == MAGIC.len() && prefix == *MAGIC {
        let header = read_encrypted_header(&mut file)?;
        return Ok(parse_header(&header)?.info.plaintext_len);
    }
    Ok(file.metadata()?.len())
}

pub fn verify_file(keyring: &Keyring, path: &Path) -> Result<EnvelopeInfo> {
    let mut file = File::open(path)?;
    let encoded_len = file.metadata()?.len();
    let header = read_encrypted_header(&mut file)?;
    let layout = EncryptedLayout::from_header_with_keyring(keyring, &header)?;
    let mut end = layout.body_offset as u64;
    for index in 0..layout.chunk_count() {
        let range = layout.encrypted_chunk_range(index)?;
        if range.end > encoded_len {
            return Err(corruption("truncated encrypted chunk frame"));
        }
        let frame_len = usize::try_from(range.end - range.start)
            .map_err(|_| corruption("encrypted chunk frame exceeds usize"))?;
        let mut frame = Zeroizing::new(vec![0_u8; frame_len]);
        file.seek(SeekFrom::Start(range.start))?;
        file.read_exact(&mut frame)?;
        let mut plaintext = layout.decrypt_chunk_frame(index, &frame)?;
        plaintext.zeroize();
        end = range.end;
    }
    if end != encoded_len {
        return Err(corruption("encrypted file length mismatch"));
    }
    Ok(layout.info().clone())
}

pub fn inspect_tree(root: &Path) -> Result<EncryptionTreeReport> {
    let mut report = EncryptionTreeReport::default();
    walk_files(root, &mut |path| {
        let metadata = fs::metadata(path)?;
        match inspect_persisted_file(path, None)? {
            Some(key_ids) => {
                report.encrypted_files = report.encrypted_files.saturating_add(1);
                report.encrypted_bytes = report.encrypted_bytes.saturating_add(metadata.len());
                report.key_ids.extend(key_ids);
                if report.key_ids.len() > MAX_TREE_KEY_IDS {
                    return Err(corruption("encrypted tree has too many key IDs"));
                }
            }
            None if !is_bootstrap_file(path) => {
                report.plaintext_files = report.plaintext_files.saturating_add(1);
                report.plaintext_bytes = report.plaintext_bytes.saturating_add(metadata.len());
                if report.plaintext_paths.len() < 16 {
                    report.plaintext_paths.push(path.display().to_string());
                }
            }
            None => {}
        }
        Ok(())
    })?;
    Ok(report)
}

pub fn verify_tree(keyring: &Keyring, root: &Path) -> Result<EncryptionTreeReport> {
    let report = inspect_tree(root)?;
    if report.plaintext_files > 0 {
        return Err(GaussError::InvalidRequest(format!(
            "persisted tree contains {} plaintext files: {}",
            report.plaintext_files,
            report.plaintext_paths.join(", ")
        )));
    }
    walk_files(root, &mut |path| {
        if inspect_persisted_file(path, Some(keyring))?.is_none() && !is_bootstrap_file(path) {
            return Err(GaussError::InvalidRequest(format!(
                "unsupported persisted file {}",
                path.display()
            )));
        }
        Ok(())
    })?;
    Ok(report)
}

/// Re-wrap a file DEK with the active KEK without re-encrypting chunk bodies.
pub fn rewrap_file(keyring: &Keyring, path: &Path) -> Result<EnvelopeInfo> {
    let envelope = fs::read(path)?;
    let (info, rotated) = rewrap_envelope(keyring, &envelope)?;
    atomic_write(path, &rotated)?;
    Ok(info)
}

fn rewrap_envelope(keyring: &Keyring, envelope: &[u8]) -> Result<(EnvelopeInfo, Vec<u8>)> {
    let parsed = parse_header(envelope)?;
    let mut dek = parsed.wrapped_dek.to_vec();
    open_in_place(
        keyring.key(&parsed.info.key_id)?,
        parsed.wrap_nonce,
        parsed.aad_header,
        &mut dek,
    )?;
    let rng = SystemRandom::new();
    let mut wrap_nonce = [0_u8; NONCE_LEN];
    rng.fill(&mut wrap_nonce)
        .map_err(|_| GaussError::InvalidRequest("OS RNG failed".to_string()))?;
    let key_id = keyring.active_key_id().as_bytes();
    let mut aad_header = Vec::with_capacity(FIXED_HEADER_LEN + key_id.len());
    aad_header.extend_from_slice(MAGIC);
    aad_header.push(1);
    aad_header.push(parsed.info.file_type as u8);
    aad_header.extend_from_slice(&(key_id.len() as u16).to_le_bytes());
    aad_header.extend_from_slice(parsed.info.file_uuid.as_bytes());
    aad_header.extend_from_slice(&parsed.info.plaintext_len.to_le_bytes());
    aad_header.extend_from_slice(&(parsed.info.chunk_size as u32).to_le_bytes());
    aad_header.extend_from_slice(&wrap_nonce);
    aad_header.extend_from_slice(&((dek.len() + TAG_LEN) as u16).to_le_bytes());
    aad_header.extend_from_slice(key_id);
    let mut wrapped_dek = dek.clone();
    seal_in_place(
        keyring.key(keyring.active_key_id())?,
        wrap_nonce,
        &aad_header,
        &mut wrapped_dek,
    )?;
    dek.zeroize();
    let mut rotated = aad_header;
    rotated.extend_from_slice(&wrapped_dek);
    rotated.extend_from_slice(&envelope[parsed.body_offset..]);
    let info = parse_header(&rotated)?.info;
    Ok((info, rotated))
}

fn validate_rotation_frontier(root: &Path) -> Result<()> {
    let marker = root.join(".protected-installation");
    match fs::read(marker) {
        Ok(bytes) if bytes.starts_with(b"CHRNINSTALL7\n") => Err(GaussError::InvalidRequest(
            "key rewrapping is not qualified for common-frontier format 1; retain the existing keyring".into())),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub fn rewrap_tree(keyring: &Keyring, root: &Path) -> Result<u64> {
    validate_rotation_frontier(root)?;
    let mut rotated = 0_u64;
    walk_files(root, &mut |path| {
        let bytes = fs::read(path)?;
        match classify_persisted_file(path, &bytes)? {
            PersistedFileKind::Encrypted(infos)
                if infos
                    .iter()
                    .any(|info| info.key_id != keyring.active_key_id()) =>
            {
                if is_audit_log(path) {
                    rewrap_audit_frames(keyring, path, &bytes)?;
                } else if is_encrypted(&bytes) {
                    rewrap_file(keyring, path)?;
                } else if is_wal_segment(path) {
                    rewrap_wal_frames(keyring, path, &bytes)?;
                }
                rotated = rotated.saturating_add(1);
            }
            PersistedFileKind::Encrypted(_) | PersistedFileKind::Bootstrap => {}
            PersistedFileKind::Plaintext => {
                return Err(GaussError::InvalidRequest(format!(
                    "cannot rotate mixed plaintext/encrypted tree: {}",
                    path.display()
                )));
            }
        }
        Ok(())
    })?;
    Ok(rotated)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct KeyRotationJournal {
    schema_version: u8,
    operation: String,
    active_key_id: String,
    logical_digest: String,
    phase: String,
}

/// Content identity for an offline persisted tree. Envelope bytes, wrapped
/// DEKs and per-frame encryption are deliberately normalized away; relative
/// paths and decoded plaintext remain authoritative. Raw-byte-derived indexes
/// are rebuilt and verified separately after their children are rewritten.
pub fn logical_tree_digest(root: &Path, keyring: Option<&Keyring>) -> Result<String> {
    let mut files = Vec::new();
    walk_files(root, &mut |path| {
        if logical_digest_excludes(path) {
            return Ok(());
        }
        let relative = path.strip_prefix(root).map_err(|_| {
            GaussError::InvalidRequest(format!(
                "persisted path escapes digest root: {}",
                path.display()
            ))
        })?;
        let relative = relative.to_str().ok_or_else(|| {
            GaussError::InvalidRequest(format!(
                "persisted path is not valid UTF-8: {}",
                path.display()
            ))
        })?;
        let bytes = fs::read(path)?;
        let plaintext = canonical_plaintext(path, &bytes, keyring)?;
        files.push((relative.as_bytes().to_vec(), plaintext));
        Ok(())
    })?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256::new();
    hasher.update(b"CHIRON-LOGICAL-TREE-V1\0");
    for (path, plaintext) in files {
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path);
        hasher.update((plaintext.len() as u64).to_le_bytes());
        hasher.update(plaintext);
    }
    Ok(hex_digest(&hasher.finalize()))
}

fn logical_digest_excludes(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "wal.manifest.json"
                    | "cold_index.gdx"
                    | ".chirondb.lock"
                    | ".generation-migration.json"
                    | ".key-rotation.json"
            )
        })
}

fn canonical_plaintext(path: &Path, bytes: &[u8], keyring: Option<&Keyring>) -> Result<Vec<u8>> {
    if is_audit_log(path) {
        return canonical_audit_plaintext(bytes, keyring);
    }
    if is_encrypted(bytes) {
        let keyring = keyring.ok_or_else(|| {
            GaussError::InvalidRequest(format!(
                "keyring required to digest encrypted file {}",
                path.display()
            ))
        })?;
        return decrypt_bytes(keyring, bytes).map(|(_, plaintext)| plaintext);
    }
    if is_wal_segment(path) && inspect_wal_frames(bytes)?.is_some() {
        return canonical_wal_plaintext(bytes, keyring);
    }
    Ok(bytes.to_vec())
}

fn canonical_audit_plaintext(bytes: &[u8], keyring: Option<&Keyring>) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes).map_err(|_| corruption("audit log is not UTF-8"))?;
    let encrypted = inspect_audit_frames(bytes)?.is_some();
    let mut output = Vec::with_capacity(bytes.len());
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        if encrypted {
            let keyring = keyring.ok_or_else(|| {
                GaussError::InvalidRequest("keyring required to digest encrypted audit".into())
            })?;
            let envelope = STANDARD
                .decode(
                    line.strip_prefix("CHIRENC1:")
                        .expect("encrypted audit was inspected"),
                )
                .map_err(|_| corruption("invalid audit frame base64"))?;
            let (_, plaintext) = decrypt_bytes(keyring, &envelope)?;
            output.extend_from_slice(&plaintext);
        } else {
            output.extend_from_slice(line.as_bytes());
        }
        output.push(b'\n');
    }
    Ok(output)
}

fn canonical_wal_plaintext(bytes: &[u8], keyring: Option<&Keyring>) -> Result<Vec<u8>> {
    let keyring = keyring.ok_or_else(|| {
        GaussError::InvalidRequest("keyring required to digest encrypted WAL".into())
    })?;
    let mut output = Vec::with_capacity(bytes.len());
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("validated WAL frame length"),
        ) as usize;
        let payload_start = offset + 8;
        let payload_end = payload_start + len;
        let (_, plaintext) = decrypt_bytes(keyring, &bytes[payload_start..payload_end])?;
        let plaintext_len = u32::try_from(plaintext.len()).map_err(|_| {
            GaussError::InvalidRequest("decoded WAL record exceeds u32 length".into())
        })?;
        output.extend_from_slice(&plaintext_len.to_le_bytes());
        output.extend_from_slice(&crc32fast::hash(&plaintext).to_le_bytes());
        output.extend_from_slice(&plaintext);
        offset = payload_end;
    }
    Ok(output)
}

fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("String writes cannot fail");
    }
    output
}

/// Crash-resumable KEK rotation. Every file header replacement is atomic and
/// idempotent; the durable journal makes an interrupted run explicit and a
/// subsequent invocation safely continues over already-rotated files.
pub fn rewrap_tree_resumable(keyring: &Keyring, root: &Path) -> Result<u64> {
    validate_rotation_frontier(root)?;
    let journal = root.join(".key-rotation.json");
    let logical_digest = logical_tree_digest(root, Some(keyring))?;
    if journal.exists() {
        let existing: KeyRotationJournal =
            serde_json::from_slice(&fs::read(&journal)?).map_err(|error| {
                GaussError::InvalidRequest(format!("invalid key rotation journal: {error}"))
            })?;
        if existing.schema_version != 2
            || existing.operation != "key_rotation"
            || existing.phase != "rewrapping"
            || existing.active_key_id != keyring.active_key_id()
            || existing.logical_digest != logical_digest
        {
            return Err(GaussError::InvalidRequest(
                "key rotation journal does not match the requested key or logical tree".into(),
            ));
        }
    } else {
        let bytes = serde_json::to_vec_pretty(&KeyRotationJournal {
            schema_version: 2,
            operation: "key_rotation".to_string(),
            active_key_id: keyring.active_key_id().to_string(),
            logical_digest: logical_digest.clone(),
            phase: "rewrapping".to_string(),
        })?;
        atomic_write(&journal, &bytes)?;
    }
    crate::failpoint::check("rotation.after_journal")?;
    let rotated = rewrap_tree(keyring, root)?;
    crate::wal::refresh_archive_manifests_for_encryption(root, keyring)?;
    crate::segment::refresh_cold_indexes_for_encryption(root, keyring)?;
    verify_tree(keyring, root)?;
    let verified_digest = logical_tree_digest(root, Some(keyring))?;
    if verified_digest != logical_digest {
        return Err(GaussError::InvalidRequest(format!(
            "key rotation changed logical tree identity: expected {logical_digest}, found {verified_digest}"
        )));
    }
    let referenced = referenced_key_ids(root)?;
    if referenced != HashSet::from([keyring.active_key_id().to_string()]) {
        return Err(GaussError::InvalidRequest(format!(
            "key rotation retained non-active local key references: {referenced:?}"
        )));
    }
    crate::failpoint::check("rotation.after_verify")?;
    crate::fs_util::durable_remove_file(&journal)?;
    Ok(rotated)
}

pub fn referenced_key_ids(root: &Path) -> Result<HashSet<String>> {
    let mut ids = HashSet::new();
    walk_files(root, &mut |path| {
        let bytes = fs::read(path)?;
        if let PersistedFileKind::Encrypted(infos) = classify_persisted_file(path, &bytes)? {
            ids.extend(infos.into_iter().map(|info| info.key_id));
        }
        Ok(())
    })?;
    Ok(ids)
}

/// Encrypt a private offline copy of a persisted tree in place. Active WAL
/// files must be empty (callers compact first); immutable WAL archives are
/// encrypted as complete envelopes and remain readable by the archive loader.
pub fn migrate_plain_tree_in_place(keyring: &Keyring, root: &Path) -> Result<u64> {
    let mut migrated = u64::from(crate::wal::Wal::migrate_transaction_journal_for_encryption(
        root, keyring,
    )?);
    walk_files(root, &mut |path| {
        let bytes = fs::read(path)?;
        match classify_persisted_file(path, &bytes)? {
            PersistedFileKind::Encrypted(_) | PersistedFileKind::Bootstrap => return Ok(()),
            PersistedFileKind::Plaintext => {}
        }
        if is_audit_log(path) {
            migrate_plain_audit(keyring, path, &bytes)?;
        } else if is_wal_segment(path) && is_active_wal_segment(path) {
            if !bytes.is_empty() {
                return Err(GaussError::InvalidRequest(format!(
                    "active WAL {} must be compacted before encryption migration",
                    path.display()
                )));
            }
        } else {
            let file_type = persisted_file_type(path);
            let encrypted = encrypt_bytes(keyring, file_type, &bytes)?;
            atomic_write(path, &encrypted)?;
        }
        migrated = migrated.saturating_add(1);
        Ok(())
    })?;
    Ok(migrated)
}

pub(crate) fn inspect_wal_frames_for_migration(bytes: &[u8]) -> Result<Option<Vec<EnvelopeInfo>>> {
    inspect_wal_frames(bytes)
}

fn is_active_wal_segment(path: &Path) -> bool {
    path.parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        == Some("wal")
}

fn persisted_file_type(path: &Path) -> FileType {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if name == "audit.jsonl" {
        FileType::Audit
    } else if name.ends_with(".gdwal") || name == "wal.base" {
        FileType::Wal
    } else if name.contains("raft") {
        FileType::Raft
    } else if name == "snapshot.json" {
        FileType::Snapshot
    } else if name == crate::graph_identity::GRAPH_IDENTITY_FILE {
        FileType::Metadata
    } else if name.ends_with(".gdx") {
        FileType::Segment
    } else {
        FileType::Metadata
    }
}

pub fn migrate_plain_audit_file(keyring: &Keyring, path: &Path) -> Result<()> {
    let bytes = fs::read(path)?;
    migrate_plain_audit(keyring, path, &bytes)
}

fn migrate_plain_audit(keyring: &Keyring, path: &Path, bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).map_err(|_| corruption("audit log is not UTF-8"))?;
    let mut output = Vec::with_capacity(bytes.len());
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        serde_json::from_str::<serde_json::Value>(line)
            .map_err(|_| corruption("plaintext audit record is not valid JSON"))?;
        let envelope = encrypt_bytes(keyring, FileType::Audit, line.as_bytes())?;
        output.extend_from_slice(b"CHIRENC1:");
        output.extend_from_slice(STANDARD.encode(envelope).as_bytes());
        output.push(b'\n');
    }
    atomic_write(path, &output)
}

enum PersistedFileKind {
    Encrypted(Vec<EnvelopeInfo>),
    Plaintext,
    Bootstrap,
}

fn classify_persisted_file(path: &Path, bytes: &[u8]) -> Result<PersistedFileKind> {
    if is_audit_log(path) {
        return Ok(match inspect_audit_frames(bytes)? {
            Some(infos) => PersistedFileKind::Encrypted(infos),
            None => PersistedFileKind::Plaintext,
        });
    }
    if is_encrypted(bytes) {
        return Ok(PersistedFileKind::Encrypted(vec![
            parse_header(bytes)?.info,
        ]));
    }
    if is_wal_segment(path) {
        return Ok(match inspect_wal_frames(bytes)? {
            Some(infos) => PersistedFileKind::Encrypted(infos),
            None => PersistedFileKind::Plaintext,
        });
    }
    if is_bootstrap_file(path) {
        return Ok(PersistedFileKind::Bootstrap);
    }
    Ok(PersistedFileKind::Plaintext)
}

fn is_bootstrap_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|name| name.to_str());
    let bootstrap_current = name == Some("CURRENT")
        && path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some("overlays");
    bootstrap_current
        || name.is_some_and(|name| {
            matches!(
                name,
                ".chirondb.lock"
                    | ".generation-migration.json"
                    | ".key-rotation.json"
                    | ".protected-installation"
            )
        })
}

/// Inspect one persisted file with memory bounded by a single WAL/audit
/// frame or encrypted chunk. Backup and restore use this on large trees.
fn inspect_persisted_file(
    path: &Path,
    keyring: Option<&Keyring>,
) -> Result<Option<HashSet<String>>> {
    if is_audit_log(path) {
        return inspect_audit_file(path, keyring);
    }
    let mut file = File::open(path)?;
    let mut prefix = [0_u8; MAGIC.len()];
    let prefix_len = file.read(&mut prefix)?;
    if prefix_len == MAGIC.len() && prefix == *MAGIC {
        let info = if let Some(keyring) = keyring {
            verify_file(keyring, path)?
        } else {
            let header = read_encrypted_header(&mut file)?;
            parse_header(&header)?.info
        };
        return Ok(Some(HashSet::from([info.key_id])));
    }
    if is_wal_segment(path) {
        return inspect_wal_file(path, keyring);
    }
    Ok(None)
}

fn inspect_wal_file(path: &Path, keyring: Option<&Keyring>) -> Result<Option<HashSet<String>>> {
    const MAX_WAL_RECORD: usize = 64 * 1024 * 1024;
    let mut reader = BufReader::new(File::open(path)?);
    let mut keys = HashSet::new();
    loop {
        let mut header = [0_u8; 8];
        if reader.read(&mut header[..1])? == 0 {
            return Ok(Some(keys));
        }
        reader
            .read_exact(&mut header[1..])
            .map_err(|_| corruption("partial WAL frame header"))?;
        let len = u32::from_le_bytes(header[..4].try_into().expect("WAL frame length")) as usize;
        if len > MAX_WAL_RECORD {
            return Err(corruption("WAL frame exceeds maximum size"));
        }
        let mut payload = Zeroizing::new(vec![0_u8; len]);
        reader
            .read_exact(&mut payload)
            .map_err(|_| corruption("partial WAL frame payload"))?;
        if crc32fast::hash(&payload)
            != u32::from_le_bytes(header[4..].try_into().expect("WAL frame CRC"))
        {
            return Err(corruption("WAL frame CRC mismatch"));
        }
        if !is_encrypted(&payload) {
            return Ok(None);
        }
        let info = if let Some(keyring) = keyring {
            let (info, mut plaintext) = decrypt_bytes(keyring, &payload)?;
            plaintext.zeroize();
            info
        } else {
            parse_header(&payload)?.info
        };
        record_tree_key_id(&mut keys, info.key_id)?;
    }
}

fn inspect_audit_file(path: &Path, keyring: Option<&Keyring>) -> Result<Option<HashSet<String>>> {
    const MAX_AUDIT_LINE: usize = 128 * 1024 * 1024;
    let mut reader = BufReader::new(File::open(path)?);
    let mut keys = HashSet::new();
    let mut line = Vec::new();
    while read_bounded_line(&mut reader, &mut line, MAX_AUDIT_LINE)? {
        let text = std::str::from_utf8(&line).map_err(|_| corruption("audit log is not UTF-8"))?;
        let text = text.strip_suffix('\n').unwrap_or(text);
        let text = text.strip_suffix('\r').unwrap_or(text);
        if text.is_empty() {
            continue;
        }
        let Some(encoded) = text.strip_prefix("CHIRENC1:") else {
            return Ok(None);
        };
        let envelope = Zeroizing::new(
            STANDARD
                .decode(encoded)
                .map_err(|_| corruption("invalid audit frame base64"))?,
        );
        if !is_encrypted(&envelope) {
            return Err(corruption("audit frame lacks CHIRENC1 envelope"));
        }
        let info = if let Some(keyring) = keyring {
            let (info, mut plaintext) = decrypt_bytes(keyring, &envelope)?;
            plaintext.zeroize();
            info
        } else {
            parse_header(&envelope)?.info
        };
        if info.file_type != FileType::Audit {
            return Err(corruption("audit frame has the wrong file type"));
        }
        record_tree_key_id(&mut keys, info.key_id)?;
    }
    Ok(Some(keys))
}

fn record_tree_key_id(keys: &mut HashSet<String>, id: String) -> Result<()> {
    if keys.len() >= MAX_TREE_KEY_IDS && !keys.contains(&id) {
        return Err(corruption("encrypted tree has too many key IDs"));
    }
    keys.insert(id);
    Ok(())
}

fn read_bounded_line(reader: &mut impl BufRead, line: &mut Vec<u8>, limit: usize) -> Result<bool> {
    line.clear();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(!line.is_empty());
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > limit {
            return Err(corruption("audit frame exceeds maximum size"));
        }
        let complete = available[take - 1] == b'\n';
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if complete {
            return Ok(true);
        }
    }
}

fn is_wal_segment(path: &Path) -> bool {
    path.extension().and_then(|extension| extension.to_str()) == Some("gdwal")
}

fn is_audit_log(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name == "audit.jsonl" || (name.starts_with("audit-") && name.ends_with(".jsonl"))
        })
}

fn inspect_wal_frames(bytes: &[u8]) -> Result<Option<Vec<EnvelopeInfo>>> {
    const WAL_HEADER: usize = 8;
    const MAX_WAL_RECORD: usize = 64 * 1024 * 1024;
    let mut offset = 0_usize;
    let mut infos = Vec::new();
    while offset < bytes.len() {
        let header_end = offset
            .checked_add(WAL_HEADER)
            .ok_or_else(|| corruption("WAL frame header overflow"))?;
        if header_end > bytes.len() {
            return Err(corruption("partial WAL frame header"));
        }
        let len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("WAL frame length"),
        ) as usize;
        if len > MAX_WAL_RECORD {
            return Err(corruption("WAL frame exceeds maximum size"));
        }
        let expected_crc = u32::from_le_bytes(
            bytes[offset + 4..header_end]
                .try_into()
                .expect("WAL frame CRC"),
        );
        let end = header_end
            .checked_add(len)
            .ok_or_else(|| corruption("WAL frame length overflow"))?;
        if end > bytes.len() {
            return Err(corruption("partial WAL frame payload"));
        }
        let payload = &bytes[header_end..end];
        if crc32fast::hash(payload) != expected_crc {
            return Err(corruption("WAL frame CRC mismatch"));
        }
        if !is_encrypted(payload) {
            return Ok(None);
        }
        infos.push(parse_header(payload)?.info);
        offset = end;
    }
    Ok(Some(infos))
}

fn inspect_audit_frames(bytes: &[u8]) -> Result<Option<Vec<EnvelopeInfo>>> {
    let text = std::str::from_utf8(bytes).map_err(|_| corruption("audit log is not UTF-8"))?;
    let mut infos = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let Some(encoded) = line.strip_prefix("CHIRENC1:") else {
            return Ok(None);
        };
        let envelope = STANDARD
            .decode(encoded)
            .map_err(|_| corruption("invalid audit frame base64"))?;
        if !is_encrypted(&envelope) {
            return Err(corruption("audit frame lacks CHIRENC1 envelope"));
        }
        let info = parse_header(&envelope)?.info;
        if info.file_type != FileType::Audit {
            return Err(corruption("audit frame has the wrong file type"));
        }
        infos.push(info);
    }
    Ok(Some(infos))
}

fn rewrap_wal_frames(keyring: &Keyring, path: &Path, bytes: &[u8]) -> Result<()> {
    inspect_wal_frames(bytes)?
        .ok_or_else(|| corruption("plaintext WAL frame in encrypted tree"))?;
    let mut output = Vec::with_capacity(bytes.len());
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("validated WAL frame length"),
        ) as usize;
        let payload_start = offset + 8;
        let payload_end = payload_start + len;
        let payload = &bytes[payload_start..payload_end];
        let info = parse_header(payload)?.info;
        let rotated = if info.key_id == keyring.active_key_id() {
            payload.to_vec()
        } else {
            rewrap_envelope(keyring, payload)?.1
        };
        if rotated.len() != len {
            return Err(GaussError::InvalidRequest(
                "WAL key rotation requires old and active key IDs to have equal encoded lengths"
                    .to_string(),
            ));
        }
        output.extend_from_slice(&(rotated.len() as u32).to_le_bytes());
        output.extend_from_slice(&crc32fast::hash(&rotated).to_le_bytes());
        output.extend_from_slice(&rotated);
        offset = payload_end;
    }
    atomic_write(path, &output)
}

fn rewrap_audit_frames(keyring: &Keyring, path: &Path, bytes: &[u8]) -> Result<()> {
    inspect_audit_frames(bytes)?
        .ok_or_else(|| corruption("plaintext audit frame in encrypted tree"))?;
    let text = std::str::from_utf8(bytes).map_err(|_| corruption("audit log is not UTF-8"))?;
    let mut output = Vec::with_capacity(bytes.len());
    for line in text.lines().filter(|line| !line.is_empty()) {
        let envelope = STANDARD
            .decode(
                line.strip_prefix("CHIRENC1:")
                    .expect("validated audit prefix"),
            )
            .map_err(|_| corruption("invalid audit frame base64"))?;
        let info = parse_header(&envelope)?.info;
        let rotated = if info.key_id == keyring.active_key_id() {
            envelope
        } else {
            rewrap_envelope(keyring, &envelope)?.1
        };
        output.extend_from_slice(b"CHIRENC1:");
        output.extend_from_slice(STANDARD.encode(rotated).as_bytes());
        output.push(b'\n');
    }
    atomic_write(path, &output)
}

fn walk_files(root: &Path, visit: &mut impl FnMut(&Path) -> Result<()>) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            walk_files(&entry.path(), visit)?;
        } else if entry.file_type()?.is_file() {
            visit(&entry.path())?;
        }
    }
    Ok(())
}

struct ParsedHeader<'a> {
    info: EnvelopeInfo,
    wrap_nonce: [u8; NONCE_LEN],
    aad_header: &'a [u8],
    wrapped_dek: &'a [u8],
    body_offset: usize,
}

fn parse_header(envelope: &[u8]) -> Result<ParsedHeader<'_>> {
    if envelope.len() < FIXED_HEADER_LEN || !envelope.starts_with(MAGIC) {
        return Err(corruption("missing CHIRENC1 header"));
    }
    if envelope[8] != 1 {
        return Err(corruption("unsupported encrypted envelope version"));
    }
    let file_type = FileType::try_from(envelope[9])?;
    let key_len = u16::from_le_bytes(envelope[10..12].try_into().expect("key id length")) as usize;
    if key_len == 0 || key_len > MAX_KEY_ID_BYTES {
        return Err(corruption("invalid encrypted key ID length"));
    }
    let file_uuid = Uuid::from_bytes(envelope[12..28].try_into().expect("file uuid"));
    let plaintext_len = u64::from_le_bytes(envelope[28..36].try_into().expect("plaintext length"));
    let chunk_size = u32::from_le_bytes(envelope[36..40].try_into().expect("chunk size")) as usize;
    if chunk_size == 0 || chunk_size > MAX_ENCRYPTION_CHUNK_SIZE {
        return Err(corruption("encryption chunk size exceeds supported bounds"));
    }
    let wrap_nonce: [u8; NONCE_LEN] = envelope[40..52].try_into().expect("wrap nonce");
    let wrapped_len =
        u16::from_le_bytes(envelope[52..54].try_into().expect("wrapped DEK length")) as usize;
    if wrapped_len != 32 + TAG_LEN {
        return Err(corruption("invalid wrapped DEK length"));
    }
    let key_end = FIXED_HEADER_LEN
        .checked_add(key_len)
        .ok_or_else(|| corruption("header overflow"))?;
    let header_end = key_end
        .checked_add(wrapped_len)
        .ok_or_else(|| corruption("header overflow"))?;
    if header_end > envelope.len() {
        return Err(corruption("truncated encrypted header"));
    }
    let key_id = std::str::from_utf8(&envelope[FIXED_HEADER_LEN..key_end])
        .map_err(|_| corruption("key id is not UTF-8"))?
        .to_string();
    Ok(ParsedHeader {
        info: EnvelopeInfo {
            file_type,
            key_id,
            file_uuid,
            plaintext_len,
            chunk_size,
        },
        wrap_nonce,
        aad_header: &envelope[..key_end],
        wrapped_dek: &envelope[key_end..header_end],
        body_offset: header_end,
    })
}

fn seal_in_place(
    key: &[u8],
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    value: &mut Vec<u8>,
) -> Result<()> {
    let key = LessSafeKey::new(
        UnboundKey::new(&aead::AES_256_GCM, key)
            .map_err(|_| GaussError::InvalidRequest("invalid AES-256-GCM key".to_string()))?,
    );
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), value)
        .map_err(|_| corruption("AES-GCM encryption failed"))
}

fn open_in_place(
    key: &[u8],
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    value: &mut Vec<u8>,
) -> Result<()> {
    let key = LessSafeKey::new(
        UnboundKey::new(&aead::AES_256_GCM, key)
            .map_err(|_| GaussError::InvalidRequest("invalid AES-256-GCM key".to_string()))?,
    );
    let plaintext = key
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), value)
        .map_err(|_| corruption("AES-GCM authentication failed"))?;
    let len = plaintext.len();
    value.truncate(len);
    Ok(())
}

fn chunk_nonce(uuid: Uuid, index: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0_u8; NONCE_LEN];
    nonce[..8].copy_from_slice(&uuid.as_bytes()[..8]);
    nonce[8..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn chunk_aad(
    file_type: FileType,
    file_uuid: Uuid,
    plaintext_len: u64,
    chunk_size: usize,
    index: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(42);
    aad.extend_from_slice(MAGIC);
    aad.push(1);
    aad.push(file_type as u8);
    aad.extend_from_slice(file_uuid.as_bytes());
    aad.extend_from_slice(&plaintext_len.to_le_bytes());
    aad.extend_from_slice(&(chunk_size as u32).to_le_bytes());
    aad.extend_from_slice(&index.to_le_bytes());
    aad
}

fn corruption(message: &str) -> GaussError {
    GaussError::InvalidRequest(format!("encrypted envelope corruption: {message}"))
}

#[cfg(unix)]
fn validate_keyring_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mode = fs::metadata(path)?.mode();
    // Kubernetes Secret volumes commonly become root:<pod-fs-group> 0440.
    // Owner/group read remains private to the pod; group write/execute and
    // every permission for "other" are still refused.
    if mode & 0o027 != 0 {
        return Err(GaussError::InvalidRequest(format!(
            "encryption keyring {} must be at most 0640 (no group write/execute or other access)",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_keyring_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    mod admission;
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn authenticated_excess_plaintext_is_rejected_before_output_growth() {
        let (_key, ring) = keyring();
        let original = encrypt_bytes(&ring, FileType::Wal, b"excess").unwrap();
        let parsed = parse_header(&original).unwrap();
        let mut dek = parsed.wrapped_dek.to_vec();
        open_in_place(
            ring.key(&parsed.info.key_id).unwrap(),
            parsed.wrap_nonce,
            parsed.aad_header,
            &mut dek,
        )
        .unwrap();
        let mut header = parsed.aad_header.to_vec();
        // Authenticate a one-byte declaration with a valid six-byte chunk;
        // this exercises the output bound rather than an authentication error.
        header[28..36].copy_from_slice(&1_u64.to_le_bytes());
        let mut wrapped = dek.clone();
        seal_in_place(
            ring.key(&parsed.info.key_id).unwrap(),
            parsed.wrap_nonce,
            &header,
            &mut wrapped,
        )
        .unwrap();
        let mut chunk = b"excess".to_vec();
        seal_in_place(
            &dek,
            chunk_nonce(parsed.info.file_uuid, 0),
            &chunk_aad(
                FileType::Wal,
                parsed.info.file_uuid,
                1,
                parsed.info.chunk_size,
                0,
            ),
            &mut chunk,
        )
        .unwrap();
        header.extend_from_slice(&wrapped);
        header.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        header.extend_from_slice(&chunk);
        let error = decrypt_bytes(&ring, &header).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("encrypted plaintext exceeds declared length"),
            "{error}"
        );
    }

    #[test]
    fn encrypted_tree_key_ids_refuse_growth_beyond_the_metadata_budget() {
        let mut keys = HashSet::new();
        for index in 0..MAX_TREE_KEY_IDS {
            record_tree_key_id(&mut keys, format!("key-{index:05}")).unwrap();
        }
        record_tree_key_id(&mut keys, "key-00000".into()).unwrap();
        assert!(record_tree_key_id(&mut keys, "new-key".into()).is_err());
        assert_eq!(keys.len(), MAX_TREE_KEY_IDS);
    }

    fn keyring() -> (NamedTempFile, Keyring) {
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            "{{\"version\":1,\"active_key_id\":\"test\",\"keys\":[{{\"id\":\"test\",\"key_base64\":\"{}\"}}]}}",
            STANDARD.encode([7_u8; 32])
        )
        .unwrap();
        file.flush().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let ring = Keyring::load(file.path()).unwrap();
        (file, ring)
    }

    #[test]
    fn bounded_reader_rejects_a_larger_chunk_before_opening_plaintext() {
        let (_key, ring) = keyring();
        let file = NamedTempFile::new().unwrap();
        let bytes = encrypt_bytes_with_chunk_size(
            &ring,
            FileType::Metadata,
            b"small payload",
            DEFAULT_CHUNK_SIZE * 2,
        )
        .unwrap();
        fs::write(file.path(), bytes).unwrap();
        // No process keyring is installed. Admission must reject the declared
        // chunk before even attempting to unwrap a key or allocate its body.
        assert!(matches!(
            open_persistent_reader_bounded(file.path(), DEFAULT_CHUNK_SIZE),
            Err(GaussError::ResourceExhausted(_))
        ));
    }

    #[test]
    fn persistent_stream_round_trips_chunk_boundaries_with_bounded_reads() {
        struct BoundedInput<'a>(&'a [u8]);
        impl Read for BoundedInput<'_> {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                assert!(output.len() <= DEFAULT_CHUNK_SIZE);
                // Exercise short input reads as well as envelope boundaries.
                let len = output.len().min(37);
                self.0.read(&mut output[..len])
            }
        }
        let (_key, ring) = keyring();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("stream");
        for encrypted in [false, true] {
            for len in [
                0,
                1,
                DEFAULT_CHUNK_SIZE - 1,
                DEFAULT_CHUNK_SIZE,
                DEFAULT_CHUNK_SIZE + 1,
                DEFAULT_CHUNK_SIZE * 3 + 17,
            ] {
                let expected = (0..len).map(|n| (n % 251) as u8).collect::<Vec<_>>();
                write_persistent_stream(
                    &path,
                    FileType::Segment,
                    len as u64,
                    BoundedInput(&expected),
                    encrypted.then_some(&ring),
                )
                .unwrap();
                let actual = fs::read(&path).unwrap();
                if encrypted {
                    assert!(is_encrypted(&actual));
                    assert_eq!(decrypt_bytes(&ring, &actual).unwrap().1, expected);
                } else {
                    assert_eq!(actual, expected);
                }
            }
        }
    }

    #[test]
    fn persistent_stream_rejects_bad_lengths_input_errors_and_failed_publication() {
        struct FailedInput;
        impl Read for FailedInput {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::StorageFull))
            }
        }
        let (_key, ring) = keyring();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("stream");
        for encrypted in [false, true] {
            let ring = encrypted.then_some(&ring);
            write_persistent_stream(&path, FileType::Segment, 3, &b"old"[..], ring).unwrap();
            let original = fs::read(&path).unwrap();
            for declared in [0, 2, 4] {
                assert!(
                    write_persistent_stream(&path, FileType::Segment, declared, &b"new"[..], ring)
                        .is_err()
                );
                assert_eq!(fs::read(&path).unwrap(), original);
                assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
            }
            assert!(
                write_persistent_stream(&path, FileType::Segment, 1, FailedInput, ring).is_err()
            );
            assert_eq!(fs::read(&path).unwrap(), original);
            let refused = directory.path().join("cannot-replace-directory");
            fs::create_dir(&refused).unwrap();
            fs::write(refused.join("sentinel"), b"old").unwrap();
            assert!(
                write_persistent_stream(&refused, FileType::Segment, 3, &b"new"[..], ring).is_err()
            );
            assert_eq!(fs::read(refused.join("sentinel")).unwrap(), b"old");
            assert_eq!(fs::read(&path).unwrap(), original);
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
            fs::remove_dir_all(refused).unwrap();
        }
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn persistent_stream_atomic_boundaries_leave_complete_old_or_new_file() {
        let (_key, ring) = keyring();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("stream");
        for encrypted in [false, true] {
            let ring = encrypted.then_some(&ring);
            for (boundary, expected) in [
                ("atomic.before_temp_sync", b"old"),
                ("atomic.after_temp_sync", b"old"),
                ("atomic.after_rename_before_dir_sync", b"new"),
            ] {
                write_persistent_stream(&path, FileType::Segment, 3, &b"old"[..], ring).unwrap();
                {
                    let _fault = crate::failpoint::test_env(
                        &format!("error:{boundary}"),
                        &directory.path().join("marker"),
                        &directory.path().join("release"),
                    );
                    assert!(
                        write_persistent_stream(&path, FileType::Segment, 3, &b"new"[..], ring)
                            .is_err()
                    );
                }
                let bytes = fs::read(&path).unwrap();
                let actual = ring.map_or_else(
                    || bytes.clone(),
                    |ring| decrypt_bytes(ring, &bytes).unwrap().1,
                );
                assert_eq!(actual, expected);
                assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
            }
        }
    }

    #[test]
    fn round_trip_and_tamper_detection() {
        let (_file, ring) = keyring();
        let plaintext = vec![42_u8; DEFAULT_CHUNK_SIZE + 17];
        let encrypted = encrypt_bytes(&ring, FileType::Segment, &plaintext).unwrap();
        let (info, decrypted) = decrypt_bytes(&ring, &encrypted).unwrap();
        assert_eq!(info.file_type, FileType::Segment);
        assert_eq!(decrypted, plaintext);

        let mut tampered = encrypted;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decrypt_bytes(&ring, &tampered).is_err());
    }

    #[test]
    fn file_uuid_makes_nonces_unique() {
        let (_file, ring) = keyring();
        let first = encrypt_bytes(&ring, FileType::Wal, b"same").unwrap();
        let second = encrypt_bytes(&ring, FileType::Wal, b"same").unwrap();
        assert_ne!(inspect(&first).file_uuid, inspect(&second).file_uuid);
        assert_ne!(first, second);
    }

    #[test]
    fn key_rotation_rewraps_only_the_header() {
        let mut old_file = NamedTempFile::new().unwrap();
        write!(
            old_file,
            "{{\"version\":1,\"active_key_id\":\"old\",\"keys\":[{{\"id\":\"old\",\"key_base64\":\"{}\"}}]}}",
            STANDARD.encode([1_u8; 32])
        )
        .unwrap();
        old_file.flush().unwrap();
        let mut new_file = NamedTempFile::new().unwrap();
        write!(
            new_file,
            "{{\"version\":1,\"active_key_id\":\"new\",\"keys\":[{{\"id\":\"old\",\"key_base64\":\"{}\"}},{{\"id\":\"new\",\"key_base64\":\"{}\"}}]}}",
            STANDARD.encode([1_u8; 32]),
            STANDARD.encode([2_u8; 32])
        )
        .unwrap();
        new_file.flush().unwrap();
        #[cfg(unix)]
        for path in [old_file.path(), new_file.path()] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let old = Keyring::load(old_file.path()).unwrap();
        let new = Keyring::load(new_file.path()).unwrap();
        let data = tempfile::tempdir().unwrap();
        let path = data.path().join("segment.enc");
        fs::write(
            &path,
            encrypt_bytes(&old, FileType::Segment, b"persisted vector").unwrap(),
        )
        .unwrap();
        let before = fs::read(&path).unwrap();
        let before_body = parse_header(&before).unwrap().body_offset;
        let info = rewrap_file(&new, &path).unwrap();
        assert_eq!(info.key_id, "new");
        let after = fs::read(&path).unwrap();
        let after_body = parse_header(&after).unwrap().body_offset;
        assert_eq!(&before[before_body..], &after[after_body..]);
        assert_eq!(decrypt_bytes(&new, &after).unwrap().1, b"persisted vector");
    }

    #[test]
    fn tree_verifier_rejects_mixed_plaintext() {
        let (_file, ring) = keyring();
        let data = tempfile::tempdir().unwrap();
        fs::write(
            data.path().join("encrypted"),
            encrypt_bytes(&ring, FileType::Metadata, b"ok").unwrap(),
        )
        .unwrap();
        fs::write(data.path().join("plaintext"), b"secret").unwrap();
        assert!(verify_tree(&ring, data.path()).is_err());
    }

    #[test]
    fn persistent_chunk_two_queue_cache_stays_bounded_and_rejects_scans() {
        let file_id = 1_u64;
        let mut cache = PersistentChunkCache::default();
        let probation_chunks = PERSISTENT_PROBATION_BYTES / DEFAULT_CHUNK_SIZE;
        let resident_chunks = PERSISTENT_CACHE_BYTES / DEFAULT_CHUNK_SIZE;

        for index in 0..resident_chunks {
            cache.insert(
                (file_id, index),
                Arc::new(CachedChunk::new(vec![0_u8; DEFAULT_CHUNK_SIZE])),
            );
        }
        assert_eq!(cache.bytes, PERSISTENT_PROBATION_BYTES);
        assert_eq!(cache.main_bytes, 0);
        assert_eq!(cache.chunks.len(), probation_chunks);

        let hot_file_id = 2_u64;
        let mut hot_cache = PersistentChunkCache::default();
        for index in 0..resident_chunks + probation_chunks {
            hot_cache.insert(
                (hot_file_id, index),
                Arc::new(CachedChunk::new(vec![0_u8; DEFAULT_CHUNK_SIZE])),
            );
            assert!(hot_cache.get((hot_file_id, index)).is_some());
        }
        assert!(hot_cache.probation_bytes <= PERSISTENT_PROBATION_BYTES);
        assert!(hot_cache.main_bytes <= PERSISTENT_MAIN_BYTES);
        assert!(hot_cache.bytes <= PERSISTENT_CACHE_BYTES);
        assert!(hot_cache.get((hot_file_id, resident_chunks)).is_some());
    }

    #[test]
    fn persistent_chunk_cache_releases_residency_to_pressure_target() {
        let mut cache = PersistentChunkCache::default();
        for index in 0..32 {
            cache.insert(
                (3, index),
                Arc::new(CachedChunk::new(vec![0_u8; DEFAULT_CHUNK_SIZE])),
            );
            assert!(cache.get((3, index)).is_some());
        }
        cache.shrink_to(4 * DEFAULT_CHUNK_SIZE);
        assert!(cache.bytes <= 4 * DEFAULT_CHUNK_SIZE);
        assert_eq!(
            cache.bytes,
            cache.probation_bytes.saturating_add(cache.main_bytes)
        );
    }

    #[test]
    fn keyring_v1_requires_fixed_width_key_ids_for_lsn_stable_rotation() {
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            "{{\"version\":1,\"active_key_id\":\"new-key\",\"keys\":[{{\"id\":\"old\",\"key_base64\":\"{}\"}},{{\"id\":\"new-key\",\"key_base64\":\"{}\"}}]}}",
            STANDARD.encode([1_u8; 32]),
            STANDARD.encode([2_u8; 32])
        )
        .unwrap();
        file.flush().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let error = Keyring::load(file.path()).unwrap_err();
        assert!(error.to_string().contains("equal encoded lengths"));
    }

    fn inspect(bytes: &[u8]) -> EnvelopeInfo {
        parse_header(bytes).unwrap().info
    }
}
