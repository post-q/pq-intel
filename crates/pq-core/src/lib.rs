//! Shared core for the pq-intel tools.
//!
//! The [`evidence`] module is the shared evidence and knowledge store: a
//! single SQLite-backed, append-only record of everything the pq-intel tools
//! learn about externally observable infrastructure, with content-addressed
//! artifacts and policy-driven cache reuse.

pub mod evidence;
pub mod net;

/// Expand a leading `~` to `$HOME` (CLI convenience shared by the tools;
/// systemd units pass absolute paths, so this only serves interactive use).
pub fn expand_tilde(path: &std::path::Path) -> std::path::PathBuf {
    if let Ok(rest) = path.strip_prefix("~") {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}
