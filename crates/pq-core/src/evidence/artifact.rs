//! Artifact storage: raw evidence (HTML, JSON responses, certificate DER)
//! preserved verbatim as compressed, SHA-256-content-addressed files,
//! deduplicated globally.
//!
//! Identity is the SHA-256 of the *original uncompressed bytes*; compression
//! (Zstandard) is metadata stored in the catalog. The [`ArtifactStore`] trait
//! is the seam for future backends (SQLite-blob, packed, object); v1 ships
//! the filesystem backend.
//!
//! Crash safety: write to temp → verify hash → atomically publish (rename) →
//! commit the DB reference. An interruption before the DB commit leaves an
//! orphan file (tolerated; GC is out of scope). An interruption mid-temp-file
//! leaves a temp file (tolerated, ignored by reads). A catalog row whose file
//! went missing surfaces as [`Error::ArtifactFileMissing`] on read, never as
//! silent corruption.

use crate::evidence::error::{Error, Result};
use crate::evidence::observation::{ArtifactMeta, Compression};
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Artifact backend seam. v1: filesystem only.
pub trait ArtifactStore: Send + Sync {
    /// Store content (deduplicated by hash); returns the catalog entry.
    fn put(&self, content: &[u8], content_type: &str) -> Result<ArtifactMeta>;
    /// Read artifact content back (decompressed).
    fn get(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>>;
    /// Catalog entry without reading content.
    fn meta(&self, hash: &[u8; 32]) -> Result<Option<ArtifactMeta>>;
}

/// Filesystem backend: `<root>/<2 hex>/<62 hex>` content files, catalog rows
/// in SQLite. The DB connection is shared with the owning [`Store`](super::Store).
pub struct FsArtifactStore {
    root: PathBuf,
    conn: Arc<Mutex<Connection>>,
}

impl FsArtifactStore {
    pub fn new(root: PathBuf, conn: Arc<Mutex<Connection>>) -> Self {
        Self { root, conn }
    }

    fn path_for(&self, hash: &[u8; 32], compression: Compression) -> PathBuf {
        let hexed = crate::evidence::key::hex(hash);
        let mut p = self.root.join(&hexed[..2]);
        p.push(match compression {
            Compression::Zstd => format!("{hexed}.zst"),
            Compression::None => hexed,
        });
        p
    }

    /// Publish content to its final path if not already present. Returns the
    /// path. Crash-safe: temp file → verify → atomic rename.
    fn publish_file(
        &self,
        hash: &[u8; 32],
        content: &[u8],
        compression: Compression,
    ) -> Result<PathBuf> {
        let final_path = self.path_for(hash, compression);
        if final_path.exists() {
            return Ok(final_path);
        }
        let tmp_dir = self.root.join("tmp");
        std::fs::create_dir_all(&tmp_dir)?;
        let tmp = tmp_dir.join(format!("put.{}.{}", std::process::id(), nanos()));
        // 1. write compressed payload to temp
        let payload: std::borrow::Cow<[u8]> = match compression {
            Compression::Zstd => {
                zstd::stream::encode_all(content, 3).map(std::borrow::Cow::Owned)?
            }
            Compression::None => std::borrow::Cow::Borrowed(content),
        };
        std::fs::write(&tmp, &payload)?;
        // 2. verify: read back, decompress, hash must equal the identity
        let readback = std::fs::read(&tmp)?;
        let verified = match compression {
            Compression::Zstd => zstd::stream::decode_all(&readback[..])?,
            Compression::None => readback,
        };
        let digest: [u8; 32] = Sha256::digest(&verified).into();
        if &digest != hash {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::ArtifactHashMismatch {
                expected: crate::evidence::key::hex(hash),
            });
        }
        // 3. atomically publish (same filesystem)
        if let Some(parent) = final_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::rename(&tmp, &final_path) {
            Ok(()) => Ok(final_path),
            // Lost a race with a concurrent publish of the same content.
            Err(_) if final_path.exists() => {
                let _ = std::fs::remove_file(&tmp);
                Ok(final_path)
            }
            Err(e) => Err(e.into()),
        }
    }
}

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

impl ArtifactStore for FsArtifactStore {
    fn put(&self, content: &[u8], content_type: &str) -> Result<ArtifactMeta> {
        let hash: [u8; 32] = Sha256::digest(content).into();
        // Dedup: catalog row present AND file on disk → done.
        if let Some(existing) = self.meta(&hash)? {
            if self.path_for(&hash, existing.compression).exists() {
                return Ok(existing);
            }
            // Catalog row without file: re-publish the file below.
            self.publish_file(&hash, content, existing.compression)?;
            return Ok(existing);
        }
        let compression = Compression::Zstd;
        self.publish_file(&hash, content, compression)?;
        // 4. commit DB reference
        let conn = self.conn.lock().expect("artifact catalog mutex");
        conn.execute(
            "INSERT OR IGNORE INTO artifacts (hash, size_uncompressed, compression, content_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                hash.as_slice(),
                content.len() as i64,
                compression.as_str(),
                content_type,
                nanos() as i64
            ],
        )?;
        let row: Option<(Vec<u8>, i64, String, String)> = conn
            .query_row(
                "SELECT hash, size_uncompressed, compression, content_type FROM artifacts WHERE hash = ?1",
                rusqlite::params![hash.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        drop(conn);
        meta_from_row(row).ok_or_else(|| Error::Misuse("artifact row vanished after insert".into()))
    }

    fn get(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let Some(meta) = self.meta(hash)? else {
            return Ok(None);
        };
        let path = self.path_for(hash, meta.compression);
        if !path.exists() {
            return Err(Error::ArtifactFileMissing(crate::evidence::key::hex(hash)));
        }
        let raw = std::fs::read(&path)?;
        let content = match meta.compression {
            Compression::Zstd => zstd::stream::decode_all(&raw[..])?,
            Compression::None => raw,
        };
        Ok(Some(content))
    }

    fn meta(&self, hash: &[u8; 32]) -> Result<Option<ArtifactMeta>> {
        let conn = self.conn.lock().expect("artifact catalog mutex");
        let row: Option<(Vec<u8>, i64, String, String)> = conn
            .query_row(
                "SELECT hash, size_uncompressed, compression, content_type FROM artifacts WHERE hash = ?1",
                rusqlite::params![hash.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        drop(conn);
        Ok(meta_from_row(row))
    }
}

fn meta_from_row(row: Option<(Vec<u8>, i64, String, String)>) -> Option<ArtifactMeta> {
    row.map(|(hash, size, compression, content_type)| {
        let mut h = [0u8; 32];
        h.copy_from_slice(&hash);
        ArtifactMeta {
            hash: h,
            size_uncompressed: size as u64,
            compression: Compression::from_str(&compression)
                .ok_or_else(|| Error::ArtifactUnknownCompression(compression.clone()))
                .expect("stored artifact with unknown compression"),
            content_type,
        }
    })
}

/// Test/inspection helper: the artifacts root directory.
impl FsArtifactStore {
    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::schema;

    fn setup() -> (tempfile::TempDir, FsArtifactStore) {
        let dir = tempfile::tempdir().unwrap();
        let conn = Connection::open(dir.path().join("evidence.db")).unwrap();
        schema::migrate(&conn).unwrap();
        let store = FsArtifactStore::new(dir.path().join("artifacts"), Arc::new(Mutex::new(conn)));
        (dir, store)
    }

    #[test]
    fn identical_content_stores_exactly_one_artifact() {
        let (_dir, store) = setup();
        let content = b"same bytes".repeat(100);
        let a = store.put(&content, "text/html").unwrap();
        let b = store.put(&content, "text/html").unwrap();
        assert_eq!(a.hash, b.hash);
        let hexed = crate::evidence::key::hex(&a.hash);
        // One content file on disk for this hash.
        let shard = store.root().join(&hexed[..2]);
        let entries: Vec<_> = std::fs::read_dir(shard)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().starts_with(&hexed))
            .collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn round_trip_through_compression() {
        let (_dir, store) = setup();
        let content: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let meta = store.put(&content, "application/octet-stream").unwrap();
        assert_eq!(meta.size_uncompressed, content.len() as u64);
        assert_eq!(meta.compression, Compression::Zstd);
        assert_eq!(meta.content_type, "application/octet-stream");
        assert_eq!(store.get(&meta.hash).unwrap().unwrap(), content);
    }

    #[test]
    fn interrupted_write_leaves_orphan_but_store_stays_consistent() {
        let (dir, store) = setup();
        let content = b"orphan simulation";
        let meta = store.put(content, "text/plain").unwrap();
        // Simulate a crash after file publish, before catalog commit, for a
        // *different* content: an orphan file in the tree.
        let orphan = dir.path().join("artifacts").join("de").join("deadbeef");
        std::fs::create_dir_all(orphan.parent().unwrap()).unwrap();
        std::fs::write(&orphan, b"orphaned junk").unwrap();
        // Store still reads existing artifacts fine and puts new ones.
        assert_eq!(store.get(&meta.hash).unwrap().unwrap(), content);
        let other = store.put(b"other content", "text/plain").unwrap();
        assert_ne!(other.hash, meta.hash);
        // Catalog row without file → honest error, not silent corruption.
        std::fs::remove_file(store.path_for(&meta.hash, meta.compression)).unwrap();
        match store.get(&meta.hash) {
            Err(Error::ArtifactFileMissing(h)) => assert_eq!(h, meta.hex()),
            other => panic!("expected ArtifactFileMissing, got {other:?}"),
        }
    }

    #[test]
    fn catalog_row_without_file_republishes_on_next_put() {
        let (_dir, store) = setup();
        let content = b"republish me".repeat(10);
        let meta = store.put(&content, "text/plain").unwrap();
        std::fs::remove_file(store.path_for(&meta.hash, meta.compression)).unwrap();
        // Same content again: catalog hit, file missing → re-publish.
        let again = store.put(&content, "text/plain").unwrap();
        assert_eq!(again.hash, meta.hash);
        assert_eq!(store.get(&meta.hash).unwrap().unwrap(), content);
    }

    #[test]
    fn missing_content_returns_none() {
        let (_dir, store) = setup();
        assert!(store.get(&[7u8; 32]).unwrap().is_none());
    }
}
