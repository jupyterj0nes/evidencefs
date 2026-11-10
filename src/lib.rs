//! One reader for forensic evidence.
//!
//! A disk image (E01, raw, split raw, VHD/VHDX, VMDK), a mounted volume, a Volume Shadow
//! Copy, a triage package (KAPE, Velociraptor, CyLR, UAC), a zip or tar archive, or a
//! single file comes in; one list of mounts comes out, each a [`fs::FileSystem`] walked,
//! searched and extracted the same way.
//!
//! ```no_run
//! use evidencefs::{Evidence, OpenOptions, WalkOptions, WalkStep};
//!
//! let ev = Evidence::open(std::path::Path::new("disk.E01"), &OpenOptions::default()).unwrap();
//! println!("{}", ev.describe());
//! for found in ev.find(&["**/config/SYSTEM", "*.evtx"], &WalkOptions::default()).unwrap() {
//!     let m = &ev.mounts[found.mount];
//!     println!("{} {} bytes", m.source_path(&found.entry.path), found.entry.size);
//! }
//! ev.walk_all(&WalkOptions::default(), &mut |mount, entry| {
//!     if entry.name.eq_ignore_ascii_case("pagefile.sys") { WalkStep::SkipDir } else { WalkStep::Continue }
//! });
//! ```
//!
//! Every failure, skip and decision is recorded with a stable `EF###` code in a per-thread
//! sink ([`diag`]); `diag::catalog()` lists them all and `docs/codes.md` explains each.

#![forbid(unsafe_code)]

pub mod archive;
pub mod carve;
pub mod diag;
pub mod error;
pub mod evidence;
pub mod extract;
pub mod fs;
pub mod source;
pub mod time;
pub mod triage;
pub mod volume;

pub use archive::ArchiveKind;
pub use carve::{CarveKind, CarveOptions, Carved};
pub use diag::{Code, Diagnostic, Severity};
pub use error::{Error, Result};
pub use evidence::{Evidence, EvidenceKind, Found, Mount, MountSource, OpenOptions};
pub use extract::{extract_file, extract_tree, ExtractOptions, ExtractStats};
pub use fs::{Entry, EntryKind, FileSystem, FsKind, Glob, Stream, WalkOptions, WalkStats, WalkStep, DELETED_DIR};
pub use source::{Image, ImageKind, SharedReader};
pub use time::{Timestamp, Timestamps};
pub use triage::{TriageInfo, TriageType};
pub use volume::{Table, Volume, VolumeKind};

/// The crate version, for the tools to print.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }

    /// `EVIDENCEFS_WRITE_DOCS=1 cargo test` rewrites `docs/codes.md`; otherwise the test
    /// checks it is current.
    #[test]
    fn codes_doc_is_current() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs").join("codes.md");
        let want = crate::diag::codes_markdown();
        if std::env::var_os("EVIDENCEFS_WRITE_DOCS").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &want).unwrap();
            return;
        }
        let have = std::fs::read_to_string(&path).unwrap_or_default().replace("\r\n", "\n");
        assert_eq!(have, want, "docs/codes.md is stale: run EVIDENCEFS_WRITE_DOCS=1 cargo test");
    }
}
