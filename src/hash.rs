use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::Error;

/// Compute the SHA-256 hex digest of a file's contents.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
pub fn sha256_file(path: &Path) -> Result<String, Error> {
    let contents = std::fs::read(path)?;
    Ok(sha256_bytes(&contents))
}

/// Compute the SHA-256 hex digest of a byte slice.
pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{result:x}")
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::{sha256_bytes, sha256_file};

    #[test]
    fn sha256_bytes_known_value() {
        // SHA-256 of empty string
        let hash = sha256_bytes(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_bytes_hello() {
        let hash = sha256_bytes(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn sha256_file_reads_and_hashes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("testfile");

        {
            let mut file = std::fs::File::create(&path).expect("create file");
            file.write_all(b"hello").expect("write");
        }

        let hash = sha256_file(&path).expect("sha256_file");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn sha256_file_missing_returns_error() {
        let result = sha256_file(std::path::Path::new("/nonexistent/file"));
        assert!(result.is_err());
    }
}
