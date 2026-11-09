//! A plain folder (a mounted volume, an unpacked triage package, a loose collection) as a
//! file system, so the tools read it the way they read an image.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::diag;
use crate::error::{Error, Result};
use crate::fs::{code as fscode, components, escapes, join, normalize, Entry, EntryKind, FileSystem, FsKind, Progress, Sink};
use crate::time::{Timestamp, Timestamps};

pub mod code {
    crate::codes! {
        FOLDER_NOT_FOUND = 550, "the folder given as evidence does not exist or is not a directory";
        FOLDER_METADATA = 551, "the metadata of an entry in the folder could not be read; permissions, a dangling link, or a path too long for the operating system";
        FOLDER_READ = 552, "a file in the folder could not be opened or read; it is locked by another process or the permissions deny it";
        FOLDER_LISTED = 553, "the folder was opened as a file system";
        FOLDER_TIMES_MISSING = 554, "the operating system gave no creation or change time for an entry; those columns are empty for it";
    }
}

/// A folder as a file system.
pub struct FolderFs {
    root: PathBuf,
}

impl FolderFs {
    /// Opens a directory.
    pub fn open(root: &Path) -> Result<Self> {
        let meta = std::fs::metadata(root).map_err(|e| Error::recorded(code::FOLDER_NOT_FOUND, format!("{}: {e}", root.display())))?;
        if !meta.is_dir() {
            return Err(Error::recorded(code::FOLDER_NOT_FOUND, format!("{}: not a directory", root.display())));
        }
        diag::info(code::FOLDER_LISTED, root.display().to_string());
        Ok(FolderFs { root: root.to_path_buf() })
    }

    /// The folder.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The host path of an evidence path.
    pub fn host_path(&self, path: &str) -> Result<PathBuf> {
        if escapes(path) {
            return Err(Error::recorded(fscode::FS_PATH_ESCAPES, path.to_string()));
        }
        let mut p = self.root.clone();
        for c in components(&normalize(path)) {
            p.push(c);
        }
        Ok(p)
    }

    fn entry(&self, evidence_path: &str, host: &Path, meta: &std::fs::Metadata) -> Entry {
        let kind = if meta.is_dir() {
            EntryKind::Dir
        } else if meta.file_type().is_symlink() {
            EntryKind::Symlink
        } else if meta.is_file() {
            EntryKind::File
        } else {
            EntryKind::Other
        };
        let mut e = Entry::new(evidence_path, kind);
        e.size = if kind == EntryKind::File { meta.len() } else { 0 };
        e.times = Timestamps { created: meta.created().ok().and_then(system_time), modified: meta.modified().ok().and_then(system_time), accessed: meta.accessed().ok().and_then(system_time), changed: changed_time(meta) };
        if e.times.created.is_none() && e.times.changed.is_none() {
            diag::info(code::FOLDER_TIMES_MISSING, evidence_path.to_string());
        }
        if kind == EntryKind::Symlink {
            e.link_target = std::fs::read_link(host).ok().map(|t| t.to_string_lossy().to_string());
        }
        e
    }
}

fn system_time(t: std::time::SystemTime) -> Option<Timestamp> {
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => Some(Timestamp::from_unix(d.as_secs() as i64, d.subsec_nanos())),
        Err(e) => {
            let d = e.duration();
            Some(Timestamp::from_unix(-(d.as_secs() as i64) - if d.subsec_nanos() > 0 { 1 } else { 0 }, if d.subsec_nanos() > 0 { 1_000_000_000 - d.subsec_nanos() } else { 0 }))
        }
    }
}

#[cfg(unix)]
fn changed_time(meta: &std::fs::Metadata) -> Option<Timestamp> {
    use std::os::unix::fs::MetadataExt;
    Some(Timestamp::from_unix(meta.ctime(), meta.ctime_nsec() as u32))
}

#[cfg(not(unix))]
fn changed_time(_meta: &std::fs::Metadata) -> Option<Timestamp> {
    None
}

impl FileSystem for FolderFs {
    fn kind(&self) -> FsKind {
        FsKind::Folder
    }

    fn label(&self) -> Option<String> {
        self.root.file_name().map(|n| n.to_string_lossy().to_string())
    }

    fn metadata(&self, path: &str) -> Result<Entry> {
        let host = self.host_path(path)?;
        let meta = std::fs::symlink_metadata(&host).map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { Error::new(fscode::FS_NOT_FOUND, path.to_string()) } else { Error::recorded(code::FOLDER_METADATA, format!("{path}: {e}")) })?;
        Ok(self.entry(&normalize(path), &host, &meta))
    }

    fn read_dir(&self, path: &str) -> Result<Vec<Entry>> {
        let host = self.host_path(path)?;
        let dir = normalize(path);
        let meta = std::fs::metadata(&host).map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { Error::new(fscode::FS_NOT_FOUND, path.to_string()) } else { Error::recorded(code::FOLDER_METADATA, format!("{path}: {e}")) })?;
        if !meta.is_dir() {
            return Err(Error::new(fscode::FS_NOT_A_DIR, path.to_string()));
        }
        let rd = std::fs::read_dir(&host).map_err(|e| Error::recorded(code::FOLDER_READ, format!("{path}: {e}")))?;
        let mut out = Vec::new();
        for item in rd {
            let item = match item {
                Ok(i) => i,
                Err(e) => {
                    diag::warn(code::FOLDER_METADATA, format!("{path}: {e}"));
                    continue;
                }
            };
            let name = item.file_name();
            let name_str = match name.to_str() {
                Some(s) => s.to_string(),
                None => {
                    diag::warn(fscode::WALK_NAME_UNDECODABLE, format!("{path}: {}", name.to_string_lossy()));
                    name.to_string_lossy().to_string()
                }
            };
            let child_path = join(&dir, &name_str);
            match std::fs::symlink_metadata(item.path()) {
                Ok(m) => out.push(self.entry(&child_path, &item.path(), &m)),
                Err(e) => {
                    diag::warn(code::FOLDER_METADATA, format!("{child_path}: {e}"));
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn copy_to(&self, path: &str, stream: Option<&str>, sink: Sink<'_>, progress: Option<Progress<'_>>) -> Result<u64> {
        let host = self.host_path(path)?;
        let meta = self.metadata(path)?;
        if meta.kind != EntryKind::File {
            return Err(Error::new(if meta.kind == EntryKind::Symlink { fscode::FS_SYMLINK_NOT_FOLLOWED } else { fscode::FS_NOT_A_FILE }, path.to_string()));
        }
        let host = match stream {
            // A host NTFS stream is addressed as name:stream.
            Some(s) if !s.is_empty() => PathBuf::from(format!("{}:{s}", host.display())),
            _ => host,
        };
        let mut f = std::fs::File::open(&host).map_err(|e| Error::recorded(if stream.is_some() { fscode::FS_STREAM_NOT_FOUND } else { code::FOLDER_READ }, format!("{path}: {e}")))?;
        let total = meta.size;
        let mut done = 0u64;
        let mut buf = vec![0u8; 1 << 20];
        let mut progress = progress;
        loop {
            let n = f.read(&mut buf).map_err(|e| Error::recorded(code::FOLDER_READ, format!("{path}: after {done} bytes: {e}")))?;
            if n == 0 {
                break;
            }
            sink.write_all(&buf[..n]).map_err(|e| Error::recorded(crate::extract::code::EXTRACT_WRITE, format!("{path}: {e}")))?;
            done += n as u64;
            if let Some(p) = progress.as_deref_mut() {
                p(done, total);
            }
        }
        Ok(done)
    }
}

impl std::fmt::Debug for FolderFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FolderFs({})", self.root.display())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::fs::{find, walk, Glob, WalkOptions, WalkStep};

    /// A small tree: /a.txt, /sub/b.bin, /sub/deep/c.txt, /empty/.
    pub fn tree(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("evidencefs-folder-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("sub").join("deep")).unwrap();
        std::fs::create_dir_all(d.join("empty")).unwrap();
        std::fs::write(d.join("a.txt"), b"alpha").unwrap();
        std::fs::write(d.join("sub").join("b.bin"), vec![1u8; 3000]).unwrap();
        std::fs::write(d.join("sub").join("deep").join("c.txt"), b"charlie").unwrap();
        d
    }

    #[test]
    fn lists_reads_and_walks() {
        crate::diag::set_quiet(true);
        let d = tree("basic");
        let fs = FolderFs::open(&d).unwrap();
        assert_eq!(fs.kind(), FsKind::Folder);
        assert_eq!(fs.label().as_deref(), d.file_name().and_then(|n| n.to_str()));
        let top = fs.read_dir("/").unwrap();
        let names: Vec<&str> = top.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a.txt", "empty", "sub"]);
        assert!(top[0].is_file() && top[1].is_dir());
        assert_eq!(top[0].size, 5);
        assert!(top[0].times.modified.is_some());
        let b = fs.metadata("sub\\b.bin").unwrap();
        assert_eq!(b.path, "/sub/b.bin");
        assert_eq!(b.size, 3000);
        assert_eq!(fs.read("/a.txt", None, 1 << 20).unwrap(), b"alpha");
        assert_eq!(fs.read_to_string("/sub/deep/c.txt", 100).unwrap(), "charlie");
        assert_eq!(fs.read("/sub/b.bin", None, 10).unwrap_err().code, fscode::FS_FILE_TOO_LARGE);
        assert!(fs.exists("/sub") && !fs.exists("/nope"));
        assert_eq!(fs.metadata("/nope").unwrap_err().code, fscode::FS_NOT_FOUND);
        assert_eq!(fs.read_dir("/a.txt").unwrap_err().code, fscode::FS_NOT_A_DIR);
        assert_eq!(fs.read_dir("/nope").unwrap_err().code, fscode::FS_NOT_FOUND);
        assert_eq!(fs.copy_to("/sub", None, &mut Vec::new(), None).unwrap_err().code, fscode::FS_NOT_A_FILE);
        assert_eq!(fs.metadata("../../etc").unwrap_err().code, fscode::FS_PATH_ESCAPES);
        // Progress is reported.
        let mut seen = Vec::new();
        let mut sink = Vec::new();
        let n = fs.copy_to("/sub/b.bin", None, &mut sink, Some(&mut |d, t| seen.push((d, t)))).unwrap();
        assert_eq!(n, 3000);
        assert_eq!(seen.last(), Some(&(3000, 3000)));
        // Walk order: directories before their content, names sorted.
        let mut order = Vec::new();
        let stats = walk(&fs, "/", &WalkOptions::default(), &mut |e| {
            order.push(e.path.clone());
            WalkStep::Continue
        });
        assert_eq!(order, vec!["/a.txt", "/empty", "/sub", "/sub/b.bin", "/sub/deep", "/sub/deep/c.txt"]);
        assert_eq!(stats.files, 3);
        assert_eq!(stats.dirs, 3);
        assert_eq!(stats.bytes, 5 + 3000 + 7);
        assert!(!stats.truncated);
        // Skip a directory.
        let mut order = Vec::new();
        walk(&fs, "/", &WalkOptions::default(), &mut |e| {
            order.push(e.path.clone());
            if e.name == "sub" {
                WalkStep::SkipDir
            } else {
                WalkStep::Continue
            }
        });
        assert_eq!(order, vec!["/a.txt", "/empty", "/sub"]);
        // Stop.
        let mut count = 0;
        let stats = walk(&fs, "/", &WalkOptions::default(), &mut |_| {
            count += 1;
            WalkStep::Stop
        });
        assert_eq!(count, 1);
        assert!(stats.truncated);
        // Depth limit and file limit.
        crate::diag::drain();
        let stats = walk(&fs, "/", &WalkOptions { max_depth: 1, ..Default::default() }, &mut |_| WalkStep::Continue);
        assert_eq!(stats.entries(), 3);
        assert!(stats.truncated && crate::diag::has(fscode::WALK_DEPTH_LIMIT));
        crate::diag::drain();
        let stats = walk(&fs, "/", &WalkOptions { max_files: 2, ..Default::default() }, &mut |_| WalkStep::Continue);
        assert_eq!(stats.entries(), 2);
        assert!(crate::diag::has(fscode::WALK_FILE_LIMIT));
        // skip_dirs and a subtree root.
        let stats = walk(&fs, "/sub", &WalkOptions { skip_dirs: vec!["DEEP".into()], ..Default::default() }, &mut |_| WalkStep::Continue);
        assert_eq!(stats.entries(), 2);
        // find.
        let found = find(&fs, "/", &[Glob::new("*.txt").unwrap()], &WalkOptions::default());
        assert_eq!(found.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), vec!["/a.txt", "/sub/deep/c.txt"]);
        let found = find(&fs, "/", &[Glob::new("sub/**/c.txt").unwrap()], &WalkOptions::default());
        assert_eq!(found.len(), 1);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn not_a_folder() {
        crate::diag::set_quiet(true);
        let d = tree("nf");
        assert_eq!(FolderFs::open(&d.join("a.txt")).unwrap_err().code, code::FOLDER_NOT_FOUND);
        assert_eq!(FolderFs::open(&d.join("missing")).unwrap_err().code, code::FOLDER_NOT_FOUND);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn system_time_before_1970() {
        let t = std::time::UNIX_EPOCH - std::time::Duration::new(1, 500_000_000);
        let ts = system_time(t).unwrap();
        assert_eq!(ts.secs, -2);
        assert_eq!(ts.nanos, 500_000_000);
        // Windows keeps 100 ns ticks, so the nanoseconds are a multiple of 100.
        let t = std::time::UNIX_EPOCH + std::time::Duration::new(5, 700);
        assert_eq!(system_time(t).unwrap(), Timestamp::from_unix(5, 700));
    }
}
