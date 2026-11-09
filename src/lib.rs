//! One reader for forensic evidence: images, volumes, file systems, shadow copies,
//! triage packages and archives, walked as one tree.
//!
//! Skeleton: the modules below name the layers; their contents are being written.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// The crate version, for the tools to print.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
