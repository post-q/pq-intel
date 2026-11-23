//! Error type for the evidence store.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("url: {0}")]
    Url(#[from] url::ParseError),
    #[error("artifact content does not match recorded hash {expected}")]
    ArtifactHashMismatch { expected: String },
    #[error("artifact {0} referenced but its file is missing on disk")]
    ArtifactFileMissing(String),
    #[error("artifact {0} recorded in catalog but has no recognizable storage layout")]
    ArtifactUnknownCompression(String),
    #[error("another thread's in-flight collection panicked; retry")]
    CollectionLeaderPanicked,
    #[error("canonicalization error: {0}")]
    Canonicalization(String),
    #[error("store misuse: {0}")]
    Misuse(String),
}

/// Result alias for the evidence store.
pub type Result<T, E = Error> = std::result::Result<T, E>;
