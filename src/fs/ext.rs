//! ext2/3/4 volumes through the `ext4-view` crate. Symbolic links are described, not
//! followed; names are bytes on disk and are shown lossily when not UTF-8.
//!
//! Deleted files and previous versions come from the journal and directory slack
//! ([`crate::fs::extjournal`]), listed under `/$DELETED/<inode>/<path>` (a previous
//! version of a live file under `/$DELETED/<inode>.v<seq>/<path>`).

use std::io::Read;
use std::sync::{Arc, Mutex};

use ext4_view::{Ext4, Ext4Error};

use crate::diag;
use crate::error::{Error, Result};
use crate::fs::extjournal::{self, RecoveredFile, RecoveredKind, Recovery};
use crate::fs::{code as fscode, deleted_path, is_deleted_root, join, normalize, parse_deleted, Entry, EntryKind, FileSystem, FsKind, Progress, Sink, DELETED_DIR};
use crate::source::SharedReader;
use crate::time::{Timestamp, Timestamps};

pub mod code {
    crate::codes! {
        EXT_OPEN = 450, "the volume's superblock or group descriptors could not be parsed as ext2/3/4; the offset is wrong, the superblock is damaged (ext keeps backups at block group 1, 3, 5...), or the feature set is one the driver refuses";
        EXT_READ_DIR = 451, "a directory could not be listed; its blocks are damaged or the image is truncated there";
        EXT_METADATA = 452, "an inode could not be read; the inode table is damaged there, the entry is listed without times";
        EXT_READ = 453, "reading a file's content failed part-way; an extent points outside the volume or the image is truncated";
        EXT_OPENED = 454, "an ext volume was opened: label, UUID";
        EXT_NAME_UNDECODABLE = 455, "a file name is not UTF-8; it is shown lossily";
        EXT_LINK_TARGET = 456, "a symbolic link's target could not be read; the entry is listed as a link without a target";
        EXT_PATH = 457, "a path is not valid for ext4-view (empty component, NUL byte); it was refused";
    }
}

/// An ext2/3/4 volume.
pub struct ExtFs {
    fs: Ext4,
    reader: SharedReader,
    label: Option<String>,
    uuid: String,
    recovery: Mutex<Option<Arc<Recovery>>>,
}

fn ts(t: ext4_view::Timestamp) -> Timestamp {
    Timestamp::from_unix(t.seconds(), t.nanoseconds())
}

fn map_err(e: Ext4Error, path: &str) -> Error {
    match e {
        Ext4Error::NotFound => Error::new(fscode::FS_NOT_FOUND, path.to_string()),
        Ext4Error::NotADirectory => Error::new(fscode::FS_NOT_A_DIR, path.to_string()),
        Ext4Error::IsADirectory => Error::new(fscode::FS_NOT_A_FILE, path.to_string()),
        other => Error::recorded(code::EXT_METADATA, format!("{path}: {other}")),
    }
}

impl ExtFs {
    /// Opens the volume whose first byte is the start of the partition.
    pub fn open(volume: SharedReader, label_for_logs: &str) -> Result<Self> {
        let reader = volume.clone();
        let fs = Ext4::load(Box::new(volume)).map_err(|e| Error::recorded(code::EXT_OPEN, format!("{label_for_logs}: {e}")))?;
        let label = fs.label().to_str().ok().map(|s| s.trim_end_matches('\0').to_string()).filter(|s| !s.is_empty());
        let uuid = format!("{}", fs.uuid());
        diag::info(code::EXT_OPENED, format!("{label_for_logs}: label {:?}, uuid {uuid}", label.as_deref().unwrap_or("")));
        Ok(ExtFs { fs, reader, label, uuid, recovery: Mutex::new(None) })
    }

    /// The file system UUID.
    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    /// The recovery pass (journal and slack), run once and cached.
    pub fn recovery(&self, progress: Option<Progress<'_>>) -> Result<Arc<Recovery>> {
        if let Some(r) = self.recovery.lock().ok().and_then(|g| g.clone()) {
            return Ok(r);
        }
        let rec = Arc::new(extjournal::recover(self.reader.clone(), progress)?);
        if let Ok(mut g) = self.recovery.lock() {
            *g = Some(rec.clone());
        }
        Ok(rec)
    }

    fn recovered_entry(&self, f: &RecoveredFile) -> Entry {
        let mut e = Entry::new(&deleted_path(&f.id, &f.path), EntryKind::File);
        e.id = f.ino as u64;
        e.size = f.size;
        e.times = Timestamps { created: f.crtime.map(|t| Timestamp::from_unix(t as i64, 0)), modified: (f.mtime != 0).then(|| Timestamp::from_unix(f.mtime as i64, 0)), accessed: None, changed: None };
        e.deleted = true;
        e.recoverable = f.recoverable;
        e.deleted_at = f.dtime.map(|t| Timestamp::from_unix(t as i64, 0));
        if f.kind == RecoveredKind::PreviousVersion {
            e.link_target = Some(format!("previous version of {} ({})", f.path, f.source));
        }
        e
    }

    fn find_recovered<'a>(&self, rec: &'a Recovery, id: &str, path: &str) -> Result<&'a RecoveredFile> {
        rec.files.iter().find(|f| f.id == id).ok_or_else(|| Error::new(fscode::FS_DELETED_NOT_FOUND, path.to_string()))
    }

    fn entry_of(&self, path: &str, meta: &ext4_view::Metadata) -> Entry {
        let ft = meta.file_type();
        let kind = if ft.is_dir() {
            EntryKind::Dir
        } else if ft.is_symlink() {
            EntryKind::Symlink
        } else if ft.is_regular_file() {
            EntryKind::File
        } else {
            EntryKind::Other
        };
        let mut e = Entry::new(path, kind);
        e.size = if kind == EntryKind::File { meta.len() } else { 0 };
        e.times = Timestamps { created: meta.created().map(ts), modified: Some(ts(meta.modified())), accessed: Some(ts(meta.accessed())), changed: None };
        if kind == EntryKind::Symlink {
            match self.fs.read_link(path) {
                Ok(t) => e.link_target = Some(t.display().to_string()),
                Err(err) => {
                    diag::info(code::EXT_LINK_TARGET, format!("{path}: {err}"));
                }
            }
        }
        e
    }
}

impl FileSystem for ExtFs {
    fn kind(&self) -> FsKind {
        FsKind::Ext
    }

    fn label(&self) -> Option<String> {
        self.label.clone()
    }

    fn supports_deleted(&self) -> bool {
        true
    }

    fn deleted(&self, progress: Option<Progress<'_>>) -> Result<Vec<Entry>> {
        let rec = self.recovery(progress)?;
        Ok(rec.files.iter().map(|f| self.recovered_entry(f)).collect())
    }

    fn metadata(&self, path: &str) -> Result<Entry> {
        if is_deleted_root(path) {
            let mut e = Entry::new(&format!("/{DELETED_DIR}"), EntryKind::Dir);
            e.deleted = true;
            return Ok(e);
        }
        if let Some((id, _)) = parse_deleted(path) {
            let rec = self.recovery(None)?;
            return Ok(self.recovered_entry(self.find_recovered(&rec, &id, path)?));
        }
        let norm = normalize(path);
        let meta = self.fs.symlink_metadata(norm.as_str()).map_err(|e| map_err(e, path))?;
        Ok(self.entry_of(&norm, &meta))
    }

    fn read_dir(&self, path: &str) -> Result<Vec<Entry>> {
        if is_deleted_root(path) {
            return self.deleted(None);
        }
        if parse_deleted(path).is_some() {
            self.metadata(path)?;
            return Err(Error::new(fscode::FS_NOT_A_DIR, path.to_string()));
        }
        let norm = normalize(path);
        let rd = self.fs.read_dir(norm.as_str()).map_err(|e| match e {
            Ext4Error::NotADirectory => Error::new(fscode::FS_NOT_A_DIR, path.to_string()),
            Ext4Error::NotFound => Error::new(fscode::FS_NOT_FOUND, path.to_string()),
            other => Error::recorded(code::EXT_READ_DIR, format!("{path}: {other}")),
        })?;
        let mut out = Vec::new();
        for item in rd {
            let item = match item {
                Ok(i) => i,
                Err(e) => {
                    diag::warn(code::EXT_READ_DIR, format!("{path}: {e}"));
                    break;
                }
            };
            let name = match item.file_name().as_str() {
                Ok(s) => s.to_string(),
                Err(_) => {
                    let lossy = item.file_name().display().to_string();
                    diag::info(code::EXT_NAME_UNDECODABLE, format!("{norm}: {lossy}"));
                    lossy
                }
            };
            if name == "." || name == ".." {
                continue;
            }
            let child = join(&norm, &name);
            match self.fs.symlink_metadata(child.as_str()) {
                Ok(m) => out.push(self.entry_of(&child, &m)),
                Err(e) => {
                    diag::warn(code::EXT_METADATA, format!("{child}: {e}"));
                    let kind = match item.file_type() {
                        Ok(t) if t.is_dir() => EntryKind::Dir,
                        Ok(t) if t.is_symlink() => EntryKind::Symlink,
                        Ok(t) if t.is_regular_file() => EntryKind::File,
                        _ => EntryKind::Other,
                    };
                    out.push(Entry::new(&child, kind));
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn copy_to(&self, path: &str, stream: Option<&str>, sink: Sink<'_>, progress: Option<Progress<'_>>) -> Result<u64> {
        if stream.is_some_and(|s| !s.is_empty()) {
            return Err(Error::new(fscode::FS_STREAM_NOT_FOUND, path.to_string()));
        }
        if let Some((id, _)) = parse_deleted(path) {
            let rec = self.recovery(None)?;
            let f = self.find_recovered(&rec, &id, path)?;
            if !f.recoverable {
                return Err(Error::new(fscode::FS_DELETED_UNRECOVERABLE, format!("{path}: {}", if f.blocks_reused { "blocks reused" } else { "no inode copy with content" })));
            }
            return extjournal::stream(self.reader.clone(), f, sink, progress);
        }
        let norm = normalize(path);
        let meta = self.fs.symlink_metadata(norm.as_str()).map_err(|e| map_err(e, path))?;
        if meta.is_symlink() {
            return Err(Error::new(fscode::FS_SYMLINK_NOT_FOLLOWED, path.to_string()));
        }
        if meta.is_dir() {
            return Err(Error::new(fscode::FS_NOT_A_FILE, path.to_string()));
        }
        let mut f = self.fs.open(norm.as_str()).map_err(|e| map_err(e, path))?;
        let total = meta.len();
        let mut done = 0u64;
        let mut buf = vec![0u8; 1 << 20];
        let mut progress = progress;
        loop {
            let n = match f.read(&mut buf) {
                Ok(n) => n,
                Err(e) => {
                    diag::warn(code::EXT_READ, format!("{path}: after {done} of {total} bytes: {e}"));
                    return Err(Error::new(fscode::FS_READ, format!("{path}: {e}")));
                }
            };
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

impl std::fmt::Debug for ExtFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ExtFs(label {:?}, uuid {})", self.label, self.uuid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_is_not_ext() {
        crate::diag::set_quiet(true);
        crate::diag::drain();
        let r = SharedReader::from_bytes(vec![0u8; 1 << 20]);
        assert_eq!(ExtFs::open(r, "test").unwrap_err().code, code::EXT_OPEN);
        crate::diag::drain();
    }

    #[test]
    fn error_mapping() {
        assert_eq!(map_err(Ext4Error::NotFound, "/x").code, fscode::FS_NOT_FOUND);
        assert_eq!(map_err(Ext4Error::NotADirectory, "/x").code, fscode::FS_NOT_A_DIR);
        assert_eq!(map_err(Ext4Error::IsADirectory, "/x").code, fscode::FS_NOT_A_FILE);
    }
}
