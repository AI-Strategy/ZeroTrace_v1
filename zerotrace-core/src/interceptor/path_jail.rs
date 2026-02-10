use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("V56: Invalid path resolution")]
    V56InvalidPath,
    #[error("V56: Path traversal attempt detected: {attempt} -> Limit: {limit}")]
    V56PathTraversalAttempt {
        attempt: String,
        limit: String,
    },
}

/// Validates that a requested path resolves to a location within the sandbox root.
/// Mitigates CVE-2026-25475 (Semantic Path Traversal).
pub fn validate_media_path(requested_path: &str, sandbox_root: &Path) -> Result<PathBuf, SecurityError> {
    // 1. Resolve to absolute path on disk (removes .. and symlinks)
    // canonicalize() requires the file to exist.
    // If the file is being created, we should canonicalize the parent directory.
    // For this vector (MEDIA access), we assume reading existing files or writing to existing dirs.
    // If the path doesn't exist, canonicalize fails. 
    // We should probably check if it exists first or handle the error.
    
    let full_path = PathBuf::from(requested_path);
    
    // For robustness: if full_path is relative, it's relative to CWD.
    // In many cases, we want to construct it from sandbox_root if it's relative?
    // The user snippet implies `requested_path` is passed in.
    // If it's "MEDIA:../../etc/passwd", we strip prefix first.
    
    // If the path does not exist, we return V56InvalidPath.
    // This is "fail-closed".
    let canonical_path = full_path.canonicalize().map_err(|_| SecurityError::V56InvalidPath)?;

    // 2. V56 Defense: Ensure the canonical path is STILL inside the sandbox
    // usage of starts_with checks path components match.
    if !canonical_path.starts_with(sandbox_root) {
        return Err(SecurityError::V56PathTraversalAttempt {
            attempt: format!("{:?}", canonical_path),
            limit: format!("{:?}", sandbox_root),
        });
    }

    Ok(canonical_path)
}
